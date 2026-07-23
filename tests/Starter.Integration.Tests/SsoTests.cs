using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Enterprise SSO (OIDC) end to end (sso-and-scim.md section 9), driven through the
/// real /auth/sso/start + /auth/sso/callback endpoints against a loopback fake IdP:
/// OIDC validation (bad state / wrong iss / wrong aud / bad signature / expired /
/// wrong nonce / email_verified=false each rejected; only a fully-valid token
/// provisions and mints), JIT provisioning (create + membership in the SSO tenant,
/// returning match by (issuer, sub), the cross-IdP takeover blocked), domain routing
/// (verified routes, unverified/unclaimed does not, a duplicate global claim is
/// refused), and the admin config surface (non-https issuer refused at save).
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SsoTests(StarterAppFixture fixture)
{
    private const string SecretPurpose = "identity.sso.client-secret.v1";

    // --- OIDC validation --------------------------------------------------

    [Fact]
    public async Task FullyValidToken_ProvisionsUserAndMembership_AndMintsTenantSession()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);

        var email = Unique("alice") + "@sso.example";
        var callback = await RunFlowAsync(
            owner.TenantId, idp, nonce => idp.CreateIdToken("sso-sub-valid", email, nonce), cancellationToken);

        callback.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(callback, cancellationToken);
        var token = doc.RootElement.GetProperty("accessToken").GetString()!;
        // The minted session is bound to the SSO tenant.
        HttpTestHelpers.ReadClaim(token, "tid").ShouldBe(owner.TenantId.ToString());

        var userId = HttpTestHelpers.ReadSubject(token);
        (await UsersWithEmailAsync(email, cancellationToken)).ShouldBe(1);
        // A membership was JIT-provisioned in the SSO tenant, and NOT anywhere else.
        (await MembershipCountAsync(owner.TenantId, userId, cancellationToken)).ShouldBe(1);
        (await MembershipCountAsync(userId, cancellationToken)).ShouldBe(1);
        (await SsoMethodCountAsync(userId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task BadState_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);

        var start = await StartAsync($"tenantId={owner.TenantId}", cancellationToken);
        idp.NextIdToken = idp.CreateIdToken("sso-sub-badstate", "x@sso.example", start.Nonce);

        // The state query param does not match the state cookie: CSRF mismatch.
        var callback = await CallbackAsync("tampered-state", start.StateCookie, cancellationToken);
        callback.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public Task WrongIssuer_IsRejected() =>
        AssertRejectedAsync((idp, nonce) =>
            idp.CreateIdToken("s", "x@sso.example", nonce, issuer: "https://evil.example"));

    [Fact]
    public Task WrongAudience_IsRejected() =>
        AssertRejectedAsync((idp, nonce) =>
            idp.CreateIdToken("s", "x@sso.example", nonce, audience: "some-other-client"));

    [Fact]
    public Task BadSignature_IsRejected() =>
        AssertRejectedAsync((idp, nonce) =>
            idp.CreateIdToken("s", "x@sso.example", nonce, signWithWrongKey: true));

    [Fact]
    public Task ExpiredToken_IsRejected() =>
        AssertRejectedAsync((idp, nonce) => idp.CreateIdToken(
            "s", "x@sso.example", nonce,
            notBefore: DateTimeOffset.UtcNow.AddMinutes(-10),
            expires: DateTimeOffset.UtcNow.AddMinutes(-5)));

    [Fact]
    public Task WrongNonce_IsRejected() =>
        AssertRejectedAsync((idp, _) => idp.CreateIdToken("s", "x@sso.example", nonce: "not-the-nonce"));

    [Fact]
    public Task EmailVerifiedFalse_IsRejected() =>
        AssertRejectedAsync((idp, nonce) =>
            idp.CreateIdToken("s", "x@sso.example", nonce, emailVerified: false));

    // --- JIT provisioning -------------------------------------------------

    [Fact]
    public async Task ReturningUser_IsMatchedByIssuerAndSubject()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);

        var email = Unique("returning") + "@sso.example";

        var first = await RunFlowAsync(
            owner.TenantId, idp, nonce => idp.CreateIdToken("sso-sub-returning", email, nonce), cancellationToken);
        first.StatusCode.ShouldBe(HttpStatusCode.OK);
        var firstUser = HttpTestHelpers.ReadSubject(await ReadAccessTokenAsync(first, cancellationToken));

        var second = await RunFlowAsync(
            owner.TenantId, idp, nonce => idp.CreateIdToken("sso-sub-returning", email, nonce), cancellationToken);
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        var secondUser = HttpTestHelpers.ReadSubject(await ReadAccessTokenAsync(second, cancellationToken));

        // The same (issuer, sub) resolves to the SAME user: one user, one sso method.
        secondUser.ShouldBe(firstUser);
        (await UsersWithEmailAsync(email, cancellationToken)).ShouldBe(1);
        (await SsoMethodCountAsync(firstUser, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task CrossIdpTakeover_IsBlocked_ADifferentIssuerAssertingTheSameSubDoesNotMatchTheFirstUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        const string sharedSubject = "shared-subject-123";

        // Tenant 1's genuine IdP: the victim signs in and gets a user + an sso method
        // bound to issuer 1.
        var tenant1 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp1 = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(tenant1.TenantId, idp1.Issuer, enabled: true, cancellationToken);
        var victimEmail = Unique("victim") + "@corp1.example";
        var victimFlow = await RunFlowAsync(
            tenant1.TenantId, idp1, nonce => idp1.CreateIdToken(sharedSubject, victimEmail, nonce), cancellationToken);
        victimFlow.StatusCode.ShouldBe(HttpStatusCode.OK);
        var victimUserId = HttpTestHelpers.ReadSubject(await ReadAccessTokenAsync(victimFlow, cancellationToken));

        // Tenant 2's own (attacker-controlled) IdP mints a token asserting the SAME
        // sub. Every per-token check passes (its own keys/issuer), but the match is
        // on (kind=sso, issuer, sub), so issuer 2's assertion cannot resolve to the
        // victim. The attacker asserts a fresh email, so it provisions a NEW user in
        // tenant 2 - never the victim.
        var tenant2 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp2 = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(tenant2.TenantId, idp2.Issuer, enabled: true, cancellationToken);
        var intruderEmail = Unique("intruder") + "@corp2.example";
        var attackFlow = await RunFlowAsync(
            tenant2.TenantId, idp2, nonce => idp2.CreateIdToken(sharedSubject, intruderEmail, nonce), cancellationToken);
        attackFlow.StatusCode.ShouldBe(HttpStatusCode.OK);
        var resolvedUserId = HttpTestHelpers.ReadSubject(await ReadAccessTokenAsync(attackFlow, cancellationToken));

        // The same sub under a different issuer did NOT bind to the victim.
        resolvedUserId.ShouldNotBe(victimUserId);
        // The victim still has exactly one sso method (issuer 1) and no membership in
        // the attacker's tenant.
        (await SsoMethodCountAsync(victimUserId, cancellationToken)).ShouldBe(1);
        (await MembershipCountAsync(tenant2.TenantId, victimUserId, cancellationToken)).ShouldBe(0);
    }

    [Fact]
    public async Task MaliciousTenantIdp_AssertingAnExistingVerifiedUsersEmail_IsRefused_NotTakenOver()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // A genuine, verified user in tenant 1 (born verified via a full SSO flow).
        var tenant1 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp1 = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(tenant1.TenantId, idp1.Issuer, enabled: true, cancellationToken);
        var victimEmail = Unique("verified-victim") + "@corp.example";
        var victimFlow = await RunFlowAsync(
            tenant1.TenantId, idp1, nonce => idp1.CreateIdToken("victim-sub-1", victimEmail, nonce), cancellationToken);
        victimFlow.StatusCode.ShouldBe(HttpStatusCode.OK);
        var victimUserId = HttpTestHelpers.ReadSubject(await ReadAccessTokenAsync(victimFlow, cancellationToken));

        // A separate, attacker-controlled tenant 2 IdP asserts the victim's EMAIL with
        // a FRESH sub, over the UNAUTHENTICATED redirect flow (RunFlowAsync sends no
        // bearer, so confirmedUserId is null). The email-based link into a VERIFIED
        // account must fail closed, never silently merge (sso-and-scim.md section 4.3).
        var tenant2 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp2 = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(tenant2.TenantId, idp2.Issuer, enabled: true, cancellationToken);
        var attack = await RunFlowAsync(
            tenant2.TenantId, idp2, nonce => idp2.CreateIdToken("attacker-sub-2", victimEmail, nonce), cancellationToken);

        // 409 link-confirmation-required, NOT 200: no silent merge into the verified account.
        attack.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(attack, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:link-confirmation-required");
        }

        // No takeover: the victim still has exactly one sso method (issuer 1), none
        // under issuer 2, and no membership in the attacker's tenant.
        (await SsoMethodCountAsync(victimUserId, cancellationToken)).ShouldBe(1);
        (await SsoMethodCountUnderIssuerAsync(victimUserId, idp2.Issuer, cancellationToken)).ShouldBe(0);
        (await MembershipCountAsync(tenant2.TenantId, victimUserId, cancellationToken)).ShouldBe(0);
    }

    // --- Domain routing ---------------------------------------------------

    [Fact]
    public async Task VerifiedDomain_RoutesToTheOwningTenantsIdp()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);
        var domain = Unique("verified") + ".example";
        await SeedDomainAsync(owner.TenantId, domain, verified: true, cancellationToken);

        // A verified domain routes: start with an email resolves the tenant and
        // redirects to its IdP.
        var response = await StartRawAsync($"email=user@{domain}", cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Found);
        response.Headers.Location!.ToString().ShouldStartWith(idp.Issuer + "/authorize");
    }

    [Fact]
    public async Task UnverifiedDomain_DoesNotRoute()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);
        var domain = Unique("unverified") + ".example";
        await SeedDomainAsync(owner.TenantId, domain, verified: false, cancellationToken);

        // An unverified claim never routes (verified_at is the second gate).
        var response = await StartRawAsync($"email=user@{domain}", cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task UnclaimedDomain_DoesNotRoute()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await StartRawAsync($"email=user@{Unique("nobody")}.example", cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task DuplicateGlobalDomainClaim_IsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner1 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var owner2 = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var domain = Unique("shared") + ".example";

        var first = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/sso/domains", owner1.Token, new { domain }, cancellationToken);
        first.StatusCode.ShouldBe(HttpStatusCode.Created);

        // A second tenant claiming the same domain hits the GLOBAL unique index: a
        // domain is claimable by at most one tenant.
        var second = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/sso/domains", owner2.Token, new { domain }, cancellationToken);
        second.StatusCode.ShouldBe(HttpStatusCode.Conflict);
    }

    // --- Admin config surface --------------------------------------------

    [Fact]
    public async Task SetConfig_RejectsNonHttpsIssuer_ButAcceptsHttps()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var insecure = await TenantWorkflow.PutJsonAsync(
            fixture,
            "/api/v1/tenant/sso/config",
            owner.Token,
            new { issuer = "http://insecure.example", clientId = "c", clientSecret = "s", enabled = true },
            cancellationToken);
        insecure.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        var secure = await TenantWorkflow.PutJsonAsync(
            fixture,
            "/api/v1/tenant/sso/config",
            owner.Token,
            new { issuer = "https://idp.example", clientId = "c", clientSecret = "s", enabled = true },
            cancellationToken);
        secure.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    // --- helpers ----------------------------------------------------------

    private async Task AssertRejectedAsync(Func<FakeOidcProvider, string, string> buildToken)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await using var idp = await FakeOidcProvider.StartAsync();
        await SeedConfigAsync(owner.TenantId, idp.Issuer, enabled: true, cancellationToken);

        var callback = await RunFlowAsync(owner.TenantId, idp, nonce => buildToken(idp, nonce), cancellationToken);
        // Every validation miss is one generic Unauthorized.
        callback.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    /// <summary>Runs the full start -> stage -> callback flow and returns the callback response.</summary>
    private async Task<HttpResponseMessage> RunFlowAsync(
        Guid tenantId,
        FakeOidcProvider idp,
        Func<string, string> buildIdToken,
        CancellationToken cancellationToken)
    {
        var start = await StartAsync($"tenantId={tenantId}", cancellationToken);
        idp.NextIdToken = buildIdToken(start.Nonce);
        return await CallbackAsync(start.State, start.StateCookie, cancellationToken);
    }

    private async Task<(string State, string StateCookie, string Nonce)> StartAsync(
        string query, CancellationToken cancellationToken)
    {
        var response = await StartRawAsync(query, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Found);
        var stateCookie = HttpTestHelpers.ReadSetCookie(response, "starter_sso_state")!;
        var parameters = ParseQuery(response.Headers.Location!.ToString());
        return (parameters["state"], stateCookie, parameters["nonce"]);
    }

    private Task<HttpResponseMessage> StartRawAsync(string query, CancellationToken cancellationToken) =>
        fixture.Client.GetAsync($"/api/v1/auth/sso/start?{query}", cancellationToken);

    private Task<HttpResponseMessage> CallbackAsync(
        string state, string stateCookie, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"/api/v1/auth/sso/callback?state={Uri.EscapeDataString(state)}&code=any-code");
        request.Headers.Add("Cookie", $"starter_sso_state={stateCookie}");
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private async Task SeedConfigAsync(
        Guid tenantId, string issuer, bool enabled, CancellationToken cancellationToken)
    {
        // Seed the config directly with the http loopback issuer (the admin API
        // refuses non-https by design, tested separately). The secret is encrypted
        // with the app's own DataProtection key ring so the reader can decrypt it.
        using var scope = fixture.Factory.Services.CreateScope();
        var protectorProvider = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var encrypted = protectorProvider.CreateProtector(SecretPurpose).Protect("client-secret-value");

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into tenancy.sso_configs "
            + "(tenant_id, issuer, client_id, client_secret_encrypted, enabled, created_at, updated_at) "
            + "values (@t, @i, @c, @s, @e, now(), now()) "
            + "on conflict (tenant_id) do update set "
            + "issuer = excluded.issuer, client_id = excluded.client_id, "
            + "client_secret_encrypted = excluded.client_secret_encrypted, enabled = excluded.enabled",
            cancellationToken,
            ("t", tenantId),
            ("i", issuer),
            ("c", FakeOidcProvider.DefaultAudience),
            ("s", encrypted),
            ("e", enabled));
    }

    private Task SeedDomainAsync(
        Guid tenantId, string domain, bool verified, CancellationToken cancellationToken) =>
        PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into tenancy.sso_domain_claims (id, tenant_id, domain, verified_at, created_at) "
            + "values (@id, @t, @d, @v, now())",
            cancellationToken,
            ("id", Guid.NewGuid()),
            ("t", tenantId),
            ("d", domain),
            ("v", verified ? DateTimeOffset.UtcNow : (object)DBNull.Value));

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

    private Task<long> MembershipCountAsync(Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from tenancy.memberships where user_id = @u",
            cancellationToken,
            ("u", userId));

    private Task<long> SsoMethodCountAsync(Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.auth_methods where user_id = @u and kind = 'sso'",
            cancellationToken,
            ("u", userId));

    private Task<long> SsoMethodCountUnderIssuerAsync(
        Guid userId, string issuer, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.auth_methods where user_id = @u and kind = 'sso' and issuer = @i",
            cancellationToken,
            ("u", userId),
            ("i", issuer));

    private static async Task<string> ReadAccessTokenAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()!;
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
            if (equals < 0)
            {
                continue;
            }

            result[Uri.UnescapeDataString(pair[..equals])] = Uri.UnescapeDataString(pair[(equals + 1)..]);
        }

        return result;
    }

    private static string Unique(string tag) => $"{tag}-{Guid.NewGuid():N}";
}
