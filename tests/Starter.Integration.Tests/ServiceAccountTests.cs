using System.Net;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Service accounts and API keys (service-accounts.md section 10), driven through
/// the real endpoints and the real ApiKey authentication scheme. Proves: a service
/// account authenticates with its key and is authorized by its grants; RLS
/// isolation; revoke and rotate are immediate; expiry; the secret is shown once
/// and stored only hashed; owner-reserved is unreachable; the permission gate
/// treats a service account identically to a user; last_used_at is throttled; the
/// three actions are audited; and the self-escalation block (roles:manage /
/// api-keys:manage never grantable to a service account, at both assign and
/// create-with-role, while the same role assigns fine to a user).
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class ServiceAccountTests(StarterAppFixture fixture)
{
    private static readonly string[] MembersRead = ["members:read"];

    private static readonly string[] InvitationsManage = ["invitations:manage"];

    private static readonly string[] RolesManage = ["roles:manage"];

    private static readonly string[] ApiKeysManage = ["api-keys:manage"];

    private static readonly string[] OwnerReservedDelete = ["tenant:delete"];

    [Fact]
    public async Task ServiceAccount_Authenticates_AndIsAuthorized_ByItsGrants()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "reader", MembersRead, cancellationToken);

        var (_, key) = await CreateServiceAccountAsync(
            owner, new { name = "reader-bot", roleId }, cancellationToken);

        // Authenticates via Authorization: Bearer sk_... and is authorized by its
        // members:read grant.
        var members = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken);
        members.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Refused an endpoint needing a permission it lacks (invitations:manage).
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            key,
            new { email = TenantWorkflow.FreshEmail("sa-invitee"), role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(invite, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }

        // One created with no role is fail-closed: 403 everywhere.
        var (_, keylessKey) = await CreateServiceAccountAsync(
            owner, new { name = "norole-bot" }, cancellationToken);
        var refused = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", keylessKey, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ServiceAccountKey_ResolvesOnlyItsOwnTenant_RlsIsolated()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var ownerA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, ownerA.Token, "reader", MembersRead, cancellationToken);

        var (_, key) = await CreateServiceAccountAsync(ownerA, new { name = "bot", roleId }, cancellationToken);

        // The key's tid is bound to tenant A, and RLS scopes every read: the list
        // is tenant A's members (its owner), never tenant B's.
        var response = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        var userIds = doc.RootElement.EnumerateArray()
            .Select(item => item.GetProperty("userId").GetGuid())
            .ToList();
        userIds.ShouldContain(ownerA.UserId);
        userIds.ShouldNotContain(ownerB.UserId);
    }

    [Fact]
    public async Task Revocation_IsImmediate_OnTheNextRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "reader", MembersRead, cancellationToken);
        var (id, key) = await CreateServiceAccountAsync(owner, new { name = "bot", roleId }, cancellationToken);

        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/service-accounts/{id}", owner.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // No token lifetime to wait out: the very next request with the revoked key
        // is 401.
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Rotation_IsImmediate_OldKeyDies_NewKeyWorks()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "reader", MembersRead, cancellationToken);
        var (id, oldKey) = await CreateServiceAccountAsync(owner, new { name = "bot", roleId }, cancellationToken);

        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", oldKey, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        var rotate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/service-accounts/{id}/rotate", owner.Token, new { }, cancellationToken);
        rotate.StatusCode.ShouldBe(HttpStatusCode.OK);
        string newKey;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(rotate, cancellationToken))
        {
            newKey = doc.RootElement.GetProperty("key").GetString()!;
        }

        newKey.ShouldNotBe(oldKey);
        // The old secret stops working immediately; the new one works.
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", oldKey, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", newKey, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Expiry_APastExpiry_Is401()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A key born past its expiry fails to resolve at the authentication layer,
        // before any authorization, so it is 401 regardless of grants.
        var (_, key) = await CreateServiceAccountAsync(
            owner,
            new { name = "expired-bot", expiresAt = DateTimeOffset.UtcNow.AddHours(-1) },
            cancellationToken);

        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Secret_IsShownOnce_AndStoredOnlyHashed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, rawKey) = await CreateServiceAccountAsync(owner, new { name = "bot" }, cancellationToken);

        // The create response carried the raw key with the sk_ prefix.
        rawKey.ShouldStartWith("sk_");

        // The list response never carries the secret or the hash - only the prefix.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/service-accounts", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            var item = doc.RootElement.GetProperty("items").EnumerateArray()
                .Single(entry => entry.GetProperty("id").GetGuid() == id);
            item.TryGetProperty("key", out _).ShouldBeFalse();
            item.TryGetProperty("keyHash", out _).ShouldBeFalse();
            item.GetProperty("keyPrefix").GetString().ShouldBe(rawKey[..9]);
        }

        // The stored key_hash is the SHA-256 hex of the raw key, not the raw key
        // itself, and no column holds the raw secret.
        var expectedHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey)));
        var (storedHash, storedPrefix) = await ReadStoredKeyAsync(id, cancellationToken);
        storedHash.ShouldBe(expectedHash);
        storedHash.ShouldNotBe(rawKey);
        storedPrefix.ShouldBe(rawKey[..9]);
    }

    [Fact]
    public async Task OwnerReservedPermission_CannotBeMinted_NoPathInACustomRole()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A custom role can never carry an owner-reserved permission, so there is
        // no role to grant a service account owner-reserved power in the first place.
        var create = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/roles",
            owner.Token,
            new { key = "sneaky", name = "Sneaky", assignableAt = "tenant", permissions = OwnerReservedDelete },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task PermissionGate_TreatsServiceAccount_IdenticallyToAUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "inviter", InvitationsManage, cancellationToken);

        // The SAME role grants invitations:manage to a user and to a service account.
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, member.UserId, cancellationToken);
        var (_, saKey) = await CreateServiceAccountAsync(owner, new { name = "inviter-bot", roleId }, cancellationToken);

        // The same RequirePermission endpoint admits both.
        var userInvite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("by-user"), role = "member" },
            cancellationToken);
        userInvite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var saInvite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            saKey,
            new { email = TenantWorkflow.FreshEmail("by-sa"), role = "member" },
            cancellationToken);
        saInvite.StatusCode.ShouldBe(HttpStatusCode.Created);

        // And refuses a service account without it.
        var (_, keylessKey) = await CreateServiceAccountAsync(owner, new { name = "norole-bot" }, cancellationToken);
        var refused = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            keylessKey,
            new { email = TenantWorkflow.FreshEmail("by-norole"), role = "member" },
            cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task LastUsedAt_IsThrottled_AdvancesAtMostOncePerWindow()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "reader", MembersRead, cancellationToken);
        var (id, key) = await CreateServiceAccountAsync(owner, new { name = "bot", roleId }, cancellationToken);

        // The first authenticated call sets last_used_at.
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
        var firstUsedAt = await ReadLastUsedAtAsync(id, cancellationToken);
        firstUsedAt.ShouldNotBeNull();

        // A second rapid call is within the throttle window, so last_used_at does
        // not advance again.
        (await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", key, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
        var secondUsedAt = await ReadLastUsedAtAsync(id, cancellationToken);
        secondUsedAt.ShouldBe(firstUsedAt);
    }

    [Fact]
    public async Task Actions_AreAudited_CreateRotateRevoke()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (id, _) = await CreateServiceAccountAsync(owner, new { name = "audited-bot" }, cancellationToken);

        var rotate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/service-accounts/{id}/rotate", owner.Token, new { }, cancellationToken);
        rotate.StatusCode.ShouldBe(HttpStatusCode.OK);

        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/service-accounts/{id}", owner.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // Each action lands a row in the tenant audit log (async projection).
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.service_account.created&entity={id}", cancellationToken);
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.service_account.rotated&entity={id}", cancellationToken);
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.service_account.revoked&entity={id}", cancellationToken);
    }

    [Fact]
    public async Task SelfEscalation_IsBlocked_ForAServiceAccount_ButNotAUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var escalatorRole = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "escalator", RolesManage, cancellationToken);

        // The same role assigns fine to a user.
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, escalatorRole, member.UserId, cancellationToken);

        // Assigning it to a service account is refused (permission-not-automatable).
        var (accountId, _) = await CreateServiceAccountAsync(owner, new { name = "bot" }, cancellationToken);
        var assign = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/role-assignments",
            owner.Token,
            new { roleId = escalatorRole, serviceAccountId = accountId },
            cancellationToken);
        assign.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(assign, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-not-automatable");
        }

        // Create-with-initial-role is refused too, and rolls the whole create back:
        // no new service account is left behind (only the one created above).
        var createWithRole = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/service-accounts",
            owner.Token,
            new { name = "escalator-bot", roleId = escalatorRole },
            cancellationToken);
        createWithRole.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(createWithRole, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-not-automatable");
        }

        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/service-accounts", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            var items = doc.RootElement.GetProperty("items");
            items.GetArrayLength().ShouldBe(1);
            items[0].GetProperty("id").GetGuid().ShouldBe(accountId);
        }

        // api-keys:manage is the other self-escalation primitive: same refusal.
        var keymakerRole = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "keymaker", ApiKeysManage, cancellationToken);
        var assignKeymaker = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/role-assignments",
            owner.Token,
            new { roleId = keymakerRole, serviceAccountId = accountId },
            cancellationToken);
        assignKeymaker.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    // --- helpers ---------------------------------------------------------

    private async Task<(Guid Id, string Key)> CreateServiceAccountAsync(
        OwnerContext owner, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/service-accounts", owner.Token, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (doc.RootElement.GetProperty("id").GetGuid(), doc.RootElement.GetProperty("key").GetString()!);
    }

    private async Task<(string KeyHash, string KeyPrefix)> ReadStoredKeyAsync(
        Guid id, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select key_hash, key_prefix from tenancy.service_accounts where id = @id", connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        (await reader.ReadAsync(cancellationToken)).ShouldBeTrue();
        return (reader.GetString(0), reader.GetString(1));
    }

    private async Task<DateTime?> ReadLastUsedAtAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select last_used_at from tenancy.service_accounts where id = @id", connection);
        command.Parameters.AddWithValue("id", id);
        // Npgsql maps timestamptz to DateTime (UTC) over the raw admin connection.
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is DBNull or null ? null : (DateTime)value;
    }

    private async Task WaitForAuditAsync(string token, string query, CancellationToken cancellationToken)
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
}
