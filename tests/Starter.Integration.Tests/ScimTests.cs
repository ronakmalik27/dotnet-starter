using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// SCIM 2.0 Users provisioning seam (sso-and-scim.md sections 5, 9), driven through
/// the real /scim/v2 endpoints and the real dedicated SCIM auth scheme. Proves the
/// CRITICAL scope confinement (a scim_ bearer authenticates ONLY /scim/v2), the
/// create-or-ensure / get / filter / soft-deactivate / reactivate flow, that
/// born-unverified composes with the SSO claim path, cross-tenant isolation, the
/// last-owner guard, the roles/groups ignore, the token-management surface (shown
/// once, hashed at rest, rotate/revoke), the SCIM error envelope, and the
/// impersonation block on credential minting.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class ScimTests(StarterAppFixture fixture)
{
    private const string SsoSecretPurpose = "identity.sso.client-secret.v1";

    private const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";

    private const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";

    // --- CRITICAL: SCIM-token scope confinement --------------------------

    [Fact]
    public async Task ScimToken_AuthenticatesOnlyScimV2_Never_ATenantAdminOrPermissionRoute()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // The named danger: /api/v1/tenant/notifications is RequireTenant +
        // RequireAuthorization with NO permission atom. A valid SCIM bearer must NOT
        // authenticate it - the selector only routes scim_ under /scim/v2 to the Scim
        // scheme, so elsewhere it falls through to JWT and is rejected.
        var notifications = await ScimBearerAsync(
            HttpMethod.Get, "/api/v1/tenant/notifications", scimToken, body: null, cancellationToken);
        notifications.StatusCode.ShouldBeOneOf(HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);

        // A RequirePermission-gated route (members:read) is refused the same way.
        var members = await ScimBearerAsync(
            HttpMethod.Get, "/api/v1/tenant/members", scimToken, body: null, cancellationToken);
        members.StatusCode.ShouldBeOneOf(HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);

        // But the SAME token DOES work on the SCIM surface.
        var scim = await ScimBearerAsync(
            HttpMethod.Get,
            $"/scim/v2/Users?filter={Uri.EscapeDataString("userName eq \"nobody@none.example\"")}",
            scimToken,
            body: null,
            cancellationToken);
        scim.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ScimToken_OnScimV2_ButWrongOrRevoked_Is401()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // A bogus scim_ bearer never resolves -> 401.
        var bogus = await ScimBearerAsync(
            HttpMethod.Get,
            $"/scim/v2/Users?filter={Uri.EscapeDataString("userName eq \"x@y.example\"")}",
            "scim_not-a-real-token",
            body: null,
            cancellationToken);
        bogus.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Revoke the real token; the very next SCIM request with it is 401.
        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/scim/tokens/{id}", owner.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        var afterRevoke = await ScimBearerAsync(
            HttpMethod.Get,
            $"/scim/v2/Users?filter={Uri.EscapeDataString("userName eq \"x@y.example\"")}",
            scimToken,
            body: null,
            cancellationToken);
        afterRevoke.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    // --- POST /Users -----------------------------------------------------

    [Fact]
    public async Task Post_NewUser_IsBornUnverified_AndMembershipCreated_IdempotentOnRepeat()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);
        var email = Unique("new") + "@scim.example";

        var created = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimToken, new { userName = email, externalId = "ext-1" }, cancellationToken);
        created.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid userId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(created, cancellationToken))
        {
            var root = doc.RootElement;
            root.GetProperty("schemas")[0].GetString().ShouldBe(UserSchema);
            root.GetProperty("userName").GetString().ShouldBe(email);
            root.GetProperty("active").GetBoolean().ShouldBeTrue();
            root.GetProperty("externalId").GetString().ShouldBe("ext-1");
            root.GetProperty("meta").GetProperty("resourceType").GetString().ShouldBe("User");
            userId = root.GetProperty("id").GetGuid();
        }

        // Born UNVERIFIED (so a later first SSO login claims the shell) and a member.
        (await EmailVerifiedAtIsNullAsync(userId, cancellationToken)).ShouldBeTrue();
        (await MembershipCountAsync(owner.TenantId, userId, cancellationToken)).ShouldBe(1);
        (await MembershipRoleAsync(owner.TenantId, userId, cancellationToken)).ShouldBe("member");

        // Idempotent on repeat: same email -> same user, no duplicate membership.
        var repeat = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimToken, new { userName = email, externalId = "ext-1" }, cancellationToken);
        repeat.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(repeat, cancellationToken))
        {
            doc.RootElement.GetProperty("id").GetGuid().ShouldBe(userId);
        }

        (await UsersWithEmailAsync(email, cancellationToken)).ShouldBe(1);
        (await MembershipCountAsync(owner.TenantId, userId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task Post_ExistingGlobalUser_EnsuresMembershipOnly_NoNewUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimTokenA) = await CreateScimTokenAsync(tenantA, cancellationToken);

        // tenantB's owner is an existing global user. SCIM-provisioning their email
        // into tenant A must reuse that user and only ensure a membership.
        var provision = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimTokenA, new { userName = tenantB.Email }, cancellationToken);
        provision.StatusCode.ShouldBe(HttpStatusCode.Created);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(provision, cancellationToken))
        {
            doc.RootElement.GetProperty("id").GetGuid().ShouldBe(tenantB.UserId);
        }

        (await UsersWithEmailAsync(tenantB.Email, cancellationToken)).ShouldBe(1);
        (await MembershipCountAsync(tenantA.TenantId, tenantB.UserId, cancellationToken)).ShouldBe(1);
    }

    // --- SCIM + SSO seam composes ----------------------------------------

    [Fact]
    public async Task ProvisionedUnverifiedShell_IsClaimed_ByTheMembersFirstSsoLogin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);
        var email = Unique("seam") + "@sso.example";

        // Provision the member via SCIM: a born-unverified, passwordless shell + a
        // membership in the tenant.
        var provision = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimToken, new { userName = email }, cancellationToken);
        provision.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid shellUserId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(provision, cancellationToken))
        {
            shellUserId = doc.RootElement.GetProperty("id").GetGuid();
        }

        (await EmailVerifiedAtIsNullAsync(shellUserId, cancellationToken)).ShouldBeTrue();

        // Now drive the full enterprise-SSO login for that email in the same tenant.
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedSsoConfigAsync(owner.TenantId, idp.Issuer, cancellationToken);
        var callback = await RunSsoFlowAsync(
            owner.TenantId, idp, nonce => idp.CreateIdToken("scim-seam-sub", email, nonce), cancellationToken);

        // The login SUCCEEDS via ClaimUnverifiedAccount: the shell is claimed, not
        // duplicated, and the session is the SAME user.
        callback.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(callback, cancellationToken))
        {
            var token = doc.RootElement.GetProperty("accessToken").GetString()!;
            HttpTestHelpers.ReadSubject(token).ShouldBe(shellUserId);
            HttpTestHelpers.ReadClaim(token, "tid").ShouldBe(owner.TenantId.ToString());
        }

        // The shell is now verified, still one user, one membership, one sso method.
        (await EmailVerifiedAtIsNullAsync(shellUserId, cancellationToken)).ShouldBeFalse();
        (await UsersWithEmailAsync(email, cancellationToken)).ShouldBe(1);
        (await MembershipCountAsync(owner.TenantId, shellUserId, cancellationToken)).ShouldBe(1);
        (await SsoMethodCountAsync(shellUserId, cancellationToken)).ShouldBe(1);
    }

    // --- GET /Users/{id} and filter, with cross-tenant isolation ----------

    [Fact]
    public async Task Get_ById_AndFilter_AreTenantScoped_CrossTenantIs404()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimTokenA) = await CreateScimTokenAsync(tenantA, cancellationToken);
        var (_, scimTokenB) = await CreateScimTokenAsync(tenantB, cancellationToken);
        var email = Unique("iso") + "@scim.example";

        var provision = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimTokenA, new { userName = email }, cancellationToken);
        provision.StatusCode.ShouldBe(HttpStatusCode.Created);
        var userId = (await HttpTestHelpers.ReadJsonAsync(provision, cancellationToken))
            .RootElement.GetProperty("id").GetGuid();

        // Tenant A's token sees the member by id and by filter.
        var byId = await ScimBearerAsync(HttpMethod.Get, $"/scim/v2/Users/{userId}", scimTokenA, null, cancellationToken);
        byId.StatusCode.ShouldBe(HttpStatusCode.OK);

        var byFilter = await ScimBearerAsync(
            HttpMethod.Get,
            $"/scim/v2/Users?filter={Uri.EscapeDataString($"userName eq \"{email}\"")}",
            scimTokenA,
            null,
            cancellationToken);
        byFilter.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(byFilter, cancellationToken))
        {
            doc.RootElement.GetProperty("totalResults").GetInt32().ShouldBe(1);
            doc.RootElement.GetProperty("Resources")[0].GetProperty("id").GetGuid().ShouldBe(userId);
        }

        // Tenant B's token cannot see a member of tenant A: 404 by id, empty by filter.
        var crossById = await ScimBearerAsync(HttpMethod.Get, $"/scim/v2/Users/{userId}", scimTokenB, null, cancellationToken);
        crossById.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        var crossByFilter = await ScimBearerAsync(
            HttpMethod.Get,
            $"/scim/v2/Users?filter={Uri.EscapeDataString($"userName eq \"{email}\"")}",
            scimTokenB,
            null,
            cancellationToken);
        crossByFilter.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(crossByFilter, cancellationToken))
        {
            doc.RootElement.GetProperty("totalResults").GetInt32().ShouldBe(0);
        }
    }

    // --- PUT active / DELETE (soft) --------------------------------------

    [Fact]
    public async Task PutActiveFalse_Suspends_PreservesRowAndRole_EmptiesResolvedPermissions_ReactivateRestores()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // A real admin member (a tid token whose role grants members:read).
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", admin.Token, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        // SCIM PUT active=false suspends the member (soft).
        var suspend = await ScimBearerAsync(
            HttpMethod.Put, $"/scim/v2/Users/{admin.UserId}", scimToken, new { active = false }, cancellationToken);
        suspend.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(suspend, cancellationToken))
        {
            doc.RootElement.GetProperty("active").GetBoolean().ShouldBeFalse();
        }

        // The row is preserved, the role is unchanged, and the resolved permission set
        // goes empty on the next request (the resolver fails closed on non-Active).
        (await MembershipCountAsync(owner.TenantId, admin.UserId, cancellationToken)).ShouldBe(1);
        (await MembershipStatusAsync(owner.TenantId, admin.UserId, cancellationToken)).ShouldBe("suspended");
        (await MembershipRoleAsync(owner.TenantId, admin.UserId, cancellationToken)).ShouldBe("admin");
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", admin.Token, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // The deactivation is directory-driven, so its audit row records a NULL actor -
        // never the affected member (the audit log must not read as "they deactivated
        // themselves").
        var suspendActor = await WaitForAuditActorAsync(
            owner.Token, "?action=tenancy.member.suspended", cancellationToken);
        suspendActor.ShouldBeNull("a SCIM deactivation must record a null actor, never the affected member");

        // Idempotent: a second suspend is a benign no-op success.
        var suspendAgain = await ScimBearerAsync(
            HttpMethod.Put, $"/scim/v2/Users/{admin.UserId}", scimToken, new { active = false }, cancellationToken);
        suspendAgain.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Reactivate restores access.
        var reactivate = await ScimBearerAsync(
            HttpMethod.Put, $"/scim/v2/Users/{admin.UserId}", scimToken, new { active = true }, cancellationToken);
        reactivate.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await MembershipStatusAsync(owner.TenantId, admin.UserId, cancellationToken)).ShouldBe("active");
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", admin.Token, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Delete_IsSoft_NotHardDelete()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);
        var email = Unique("del") + "@scim.example";

        var provision = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimToken, new { userName = email }, cancellationToken);
        var userId = (await HttpTestHelpers.ReadJsonAsync(provision, cancellationToken))
            .RootElement.GetProperty("id").GetGuid();

        var delete = await ScimBearerAsync(
            HttpMethod.Delete, $"/scim/v2/Users/{userId}", scimToken, null, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The membership row is STILL present (soft), just suspended - never hard-deleted.
        (await MembershipCountAsync(owner.TenantId, userId, cancellationToken)).ShouldBe(1);
        (await MembershipStatusAsync(owner.TenantId, userId, cancellationToken)).ShouldBe("suspended");
    }

    [Fact]
    public async Task LastOwner_CannotBeDeactivated_ByPutOrDelete()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // The owner is the tenant's sole owner: SCIM must never suspend them.
        var putSuspend = await ScimBearerAsync(
            HttpMethod.Put, $"/scim/v2/Users/{owner.UserId}", scimToken, new { active = false }, cancellationToken);
        putSuspend.StatusCode.ShouldBe(HttpStatusCode.Conflict);

        var delete = await ScimBearerAsync(
            HttpMethod.Delete, $"/scim/v2/Users/{owner.UserId}", scimToken, null, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.Conflict);

        // Still an active owner afterwards - no lockout.
        (await MembershipStatusAsync(owner.TenantId, owner.UserId, cancellationToken)).ShouldBe("active");
        (await MembershipRoleAsync(owner.TenantId, owner.UserId, cancellationToken)).ShouldBe("owner");
    }

    // --- roles / groups are ignored (privilege-escalation guard) ----------

    [Fact]
    public async Task RolesAndGroups_AreIgnored_GrantNothing()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);
        var email = Unique("roles") + "@scim.example";

        // Okta sends roles / groups / entitlements by default; the seam must ignore them.
        var body = new
        {
            userName = email,
            roles = new[] { new { value = "admin" } },
            groups = new[] { new { value = "administrators" } },
            entitlements = new[] { new { value = "roles:manage" } },
        };
        var provision = await ScimBearerAsync(HttpMethod.Post, "/scim/v2/Users", scimToken, body, cancellationToken);
        provision.StatusCode.ShouldBe(HttpStatusCode.Created);
        var userId = (await HttpTestHelpers.ReadJsonAsync(provision, cancellationToken))
            .RootElement.GetProperty("id").GetGuid();

        // The member landed as a plain member with NO role assignments: the smuggled
        // attributes granted nothing.
        (await MembershipRoleAsync(owner.TenantId, userId, cancellationToken)).ShouldBe("member");
        (await RoleAssignmentCountAsync(owner.TenantId, userId, cancellationToken)).ShouldBe(0);
    }

    // --- token management ------------------------------------------------

    [Fact]
    public async Task Token_IsShownOnce_StoredHashed_ListNeverCarriesTheSecret()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, rawToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // The create response carried the raw token with the scim_ prefix.
        rawToken.ShouldStartWith("scim_");

        // The list carries only the display prefix - never the secret or the hash.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/scim/tokens", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            var item = doc.RootElement.EnumerateArray().Single(entry => entry.GetProperty("id").GetGuid() == id);
            item.TryGetProperty("token", out _).ShouldBeFalse();
            item.TryGetProperty("tokenHash", out _).ShouldBeFalse();
            item.GetProperty("tokenPrefix").GetString().ShouldBe(rawToken[..11]);
        }

        // The stored token_hash is the SHA-256 hex of the raw token, not the raw token.
        var expectedHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
        var storedHash = await ReadStoredHashAsync(id, cancellationToken);
        storedHash.ShouldBe(expectedHash);
        storedHash.ShouldNotBe(rawToken);
    }

    [Fact]
    public async Task Rotate_OldTokenStopsResolving_NewTokenWorks_AndIsAudited()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, oldToken) = await CreateScimTokenAsync(owner, cancellationToken);

        var filter = $"/scim/v2/Users?filter={Uri.EscapeDataString("userName eq \"x@y.example\"")}";
        (await ScimBearerAsync(HttpMethod.Get, filter, oldToken, null, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        var rotate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/scim/tokens/{id}/rotate", owner.Token, new { }, cancellationToken);
        rotate.StatusCode.ShouldBe(HttpStatusCode.OK);
        var newToken = (await HttpTestHelpers.ReadJsonAsync(rotate, cancellationToken))
            .RootElement.GetProperty("token").GetString()!;

        newToken.ShouldNotBe(oldToken);
        (await ScimBearerAsync(HttpMethod.Get, filter, oldToken, null, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await ScimBearerAsync(HttpMethod.Get, filter, newToken, null, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        // The rotation is audited on the tenant spine (async projection).
        await WaitForTenantAuditAsync(
            owner.Token, $"?action=tenancy.scim.token_rotated&entity={id}", cancellationToken);
    }

    [Fact]
    public async Task Revoke_IsIdempotent()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, _) = await CreateScimTokenAsync(owner, cancellationToken);

        var first = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/scim/tokens/{id}", owner.Token, cancellationToken);
        first.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // A second revoke of an already-revoked token is a benign success.
        var second = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/scim/tokens/{id}", owner.Token, cancellationToken);
        second.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    // --- SCIM error envelope ---------------------------------------------

    [Fact]
    public async Task BadRequest_ReturnsTheScimErrorEnvelope_NotRfc9457()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (_, scimToken) = await CreateScimTokenAsync(owner, cancellationToken);

        // A blank userName is a SCIM invalidValue.
        var bad = await ScimBearerAsync(
            HttpMethod.Post, "/scim/v2/Users", scimToken, new { userName = "" }, cancellationToken);
        bad.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using var doc = await HttpTestHelpers.ReadJsonAsync(bad, cancellationToken);
        var root = doc.RootElement;
        // The SCIM Error urn, NOT the app's starter:* problem envelope.
        root.GetProperty("schemas")[0].GetString().ShouldBe(ErrorSchema);
        root.GetProperty("status").GetString().ShouldBe("400");
        root.TryGetProperty("type", out _).ShouldBeFalse();
    }

    // --- impersonation block on credential minting -----------------------

    [Fact]
    public async Task Impersonation_Blocks_ScimTokenCreateAndRotate_AndServiceAccountCreate()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (tokenId, _) = await CreateScimTokenAsync(owner, cancellationToken);

        // Impersonate the owner (who holds settings:manage / api-keys:manage), so the
        // permission gate passes and the impersonation BLOCK is what refuses the mint.
        var (impersonation, _) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, "support", cancellationToken);

        var scimCreate = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/scim/tokens", impersonation, new { }, cancellationToken);
        scimCreate.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(scimCreate, cancellationToken)).ShouldBe("starter:impersonation-forbidden");

        var scimRotate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/scim/tokens/{tokenId}/rotate", impersonation, new { }, cancellationToken);
        scimRotate.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(scimRotate, cancellationToken)).ShouldBe("starter:impersonation-forbidden");

        // The same hardening now guards the service-account create/rotate too.
        var serviceAccount = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/service-accounts", impersonation, new { name = "bot" }, cancellationToken);
        serviceAccount.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(serviceAccount, cancellationToken)).ShouldBe("starter:impersonation-forbidden");
    }

    // --- helpers ---------------------------------------------------------

    private async Task<(Guid Id, string Token)> CreateScimTokenAsync(
        OwnerContext owner, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/scim/tokens", owner.Token, new { }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (doc.RootElement.GetProperty("id").GetGuid(), doc.RootElement.GetProperty("token").GetString()!);
    }

    private Task<HttpResponseMessage> ScimBearerAsync(
        HttpMethod method, string path, string scimToken, object? body, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scimToken);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return fixture.Client.SendAsync(request, cancellationToken);
    }

    // --- SSO flow plumbing (the SsoTests loopback-IdP pattern, condensed) ---

    private async Task SeedSsoConfigAsync(Guid tenantId, string issuer, CancellationToken cancellationToken)
    {
        using var scope = fixture.Factory.Services.CreateScope();
        var protectorProvider = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var encrypted = protectorProvider.CreateProtector(SsoSecretPurpose).Protect("client-secret-value");

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into tenancy.sso_configs "
            + "(tenant_id, issuer, client_id, client_secret_encrypted, enabled, created_at, updated_at) "
            + "values (@t, @i, @c, @s, true, now(), now()) "
            + "on conflict (tenant_id) do update set issuer = excluded.issuer, enabled = true",
            cancellationToken,
            ("t", tenantId),
            ("i", issuer),
            ("c", FakeOidcProvider.DefaultAudience),
            ("s", encrypted));
    }

    private async Task<HttpResponseMessage> RunSsoFlowAsync(
        Guid tenantId, FakeOidcProvider idp, Func<string, string> buildIdToken, CancellationToken cancellationToken)
    {
        var start = await fixture.Client.GetAsync(
            $"/api/v1/auth/sso/start?tenantId={tenantId}", cancellationToken);
        start.StatusCode.ShouldBe(HttpStatusCode.Found);
        var stateCookie = HttpTestHelpers.ReadSetCookie(start, "starter_sso_state")!;
        var parameters = ParseQuery(start.Headers.Location!.ToString());
        idp.NextIdToken = buildIdToken(parameters["nonce"]);

        using var callback = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/v1/auth/sso/callback?state={Uri.EscapeDataString(parameters["state"])}&code=any-code");
        callback.Headers.Add("Cookie", $"starter_sso_state={stateCookie}");
        return await fixture.Client.SendAsync(callback, cancellationToken);
    }

    private static Dictionary<string, string> ParseQuery(string url)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var queryStart = url.IndexOf('?', StringComparison.Ordinal);
        if (queryStart < 0)
        {
            return result;
        }

        foreach (var pair in url[(queryStart + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = pair.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
            {
                result[Uri.UnescapeDataString(pair[..equals])] = Uri.UnescapeDataString(pair[(equals + 1)..]);
            }
        }

        return result;
    }

    // --- SQL assertions (admin connection, bypasses RLS) -----------------

    private Task<long> UsersWithEmailAsync(string email, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture, "select count(*) from identity.users where email = @e", cancellationToken, ("e", email));

    private Task<long> MembershipCountAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from tenancy.memberships where tenant_id = @t and user_id = @u",
            cancellationToken,
            ("t", tenantId),
            ("u", userId));

    private Task<long> RoleAssignmentCountAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from tenancy.role_assignments "
            + "where tenant_id = @t and principal_type = 'user' and principal_id = @u",
            cancellationToken,
            ("t", tenantId),
            ("u", userId));

    private Task<long> SsoMethodCountAsync(Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.auth_methods where user_id = @u and kind = 'sso'",
            cancellationToken,
            ("u", userId));

    private async Task<bool> EmailVerifiedAtIsNullAsync(Guid userId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select email_verified_at from identity.users where id = @u", connection);
        command.Parameters.AddWithValue("u", userId);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull;
    }

    private async Task<string?> MembershipStatusAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        await ReadStringAsync(
            "select status from tenancy.memberships where tenant_id = @t and user_id = @u",
            cancellationToken,
            ("t", tenantId),
            ("u", userId));

    private async Task<string?> MembershipRoleAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        await ReadStringAsync(
            "select role from tenancy.memberships where tenant_id = @t and user_id = @u",
            cancellationToken,
            ("t", tenantId),
            ("u", userId));

    private async Task<string> ReadStoredHashAsync(Guid id, CancellationToken cancellationToken) =>
        (await ReadStringAsync(
            "select token_hash from tenancy.scim_tokens where id = @id", cancellationToken, ("id", id)))!;

    private async Task<string?> ReadStringAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, parameterValue) in parameters)
        {
            command.Parameters.AddWithValue(name, parameterValue);
        }

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? null : (string)result;
    }

    private async Task WaitForTenantAuditAsync(string token, string query, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(
                fixture, "/api/v1/tenant/audit" + query, token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            if (doc.RootElement.GetProperty("items").GetArrayLength() > 0)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No audit row for '{query}' appeared within the deadline.");
    }

    // Polls the tenant audit read until the row appears, then returns its actor: the
    // parsed actorUserId when present as a string, or null when the field is JSON null
    // or absent (a directory-driven event with no interactive actor).
    private async Task<Guid?> WaitForAuditActorAsync(
        string token, string query, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(
                fixture, "/api/v1/tenant/audit" + query, token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            var items = doc.RootElement.GetProperty("items");
            if (items.GetArrayLength() > 0)
            {
                var item = items[0];
                return item.TryGetProperty("actorUserId", out var actor)
                    && actor.ValueKind == JsonValueKind.String
                        ? Guid.Parse(actor.GetString()!)
                        : null;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No audit row for '{query}' appeared within the deadline.");
    }

    private static async Task<string?> ProblemTypeAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("type").GetString();
    }

    private static string Unique(string tag) => $"{tag}-{Guid.NewGuid():N}";
}
