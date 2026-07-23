using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Dsar;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// GDPR/DSAR data export and erasure (data-export-and-erasure.md), driven through the
/// real endpoints, the real bypass-path erasure, and the real async projections.
/// Proves: erasure purges EVERY tenant-owned table for the target and leaves every
/// other tenant intact (the safety guarantee), revokes the target's live sessions, and
/// records platform.tenant.erased on the surviving platform log; the retention gate;
/// the reactivate widening; the self-serve export bundle, its permission gate, and its
/// audited event; and the [Sensitive] secret-exclusion completeness across both
/// artifacts.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class DataExportErasureTests(StarterAppFixture fixture)
{
    private static readonly string[] NotesReadOnly = ["notes:read"];

    [Fact]
    public async Task Erasure_PurgesEveryTenantTable_LeavesOtherTenantsIntact_RevokesSessions_AndAudits()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await SeedTenantAsync(tenantA, cancellationToken);
        await SeedTenantAsync(tenantB, cancellationToken);

        // Quiesce both tenants' event pipelines so the async projections (audit log,
        // note index) have caught up and no in-flight delivery can re-create a row
        // after the purge.
        await WaitForQuiescentAsync(tenantA.TenantId, cancellationToken);
        await WaitForQuiescentAsync(tenantB.TenantId, cancellationToken);

        var tables = DeclaredTables();

        // A really has data across the tenant-owned tables (a non-vacuous purge).
        foreach (var table in RepresentativeTables(tables))
        {
            (await CountAsync(table, tenantA.TenantId, cancellationToken))
                .ShouldBeGreaterThan(0, $"tenant A should have seeded rows in {table.Table}");
        }

        // A has at least one live tenant-bound session; capture B's per-table counts
        // and live sessions so "B is intact" is an exact, before/after comparison.
        (await UnrevokedSessionsAsync(tenantA.TenantId, cancellationToken)).ShouldBeGreaterThan(0);
        var bSessionsBefore = await UnrevokedSessionsAsync(tenantB.TenantId, cancellationToken);
        bSessionsBefore.ShouldBeGreaterThan(0);
        var bCountsBefore = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var table in tables)
        {
            bCountsBefore[table.Table] = await CountAsync(table, tenantB.TenantId, cancellationToken);
        }

        // Soft-delete A, then quiesce again (the soft-delete emits its own event), so
        // the pipeline is idle before the purge.
        var softDelete = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantA.TenantId}/delete", admin.Token, new { }, cancellationToken);
        softDelete.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        await WaitForQuiescentAsync(tenantA.TenantId, cancellationToken);

        // Erase A (force: the retention window has not elapsed). Returns the operator
        // snapshot.
        var erase = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantA.TenantId}/erase", admin.Token, new { force = true }, cancellationToken);
        erase.StatusCode.ShouldBe(HttpStatusCode.OK);

        // EVERY declared tenant-owned table has zero rows for A; B is byte-for-byte
        // intact.
        foreach (var table in tables)
        {
            (await CountAsync(table, tenantA.TenantId, cancellationToken))
                .ShouldBe(0, $"tenant A rows must be purged from {table.Table}");
            (await CountAsync(table, tenantB.TenantId, cancellationToken))
                .ShouldBe(bCountsBefore[table.Table], $"tenant B rows in {table.Table} must be untouched");
        }

        // A's live sessions are revoked; B's are not.
        (await UnrevokedSessionsAsync(tenantA.TenantId, cancellationToken)).ShouldBe(0);
        (await UnrevokedSessionsAsync(tenantB.TenantId, cancellationToken)).ShouldBe(bSessionsBefore);

        // The erasure is recorded on the surviving platform audit log (never purged),
        // identifying the erased tenant.
        (await PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.platform_audit_log "
            + "where action = 'platform.tenant.erased' and data->>'tenantId' = @t",
            cancellationToken,
            ("t", tenantA.TenantId.ToString()))).ShouldBe(1);
    }

    [Fact]
    public async Task RetentionGate_BlocksNotDeleted_And_WithinWindow_UnlessForce_Or_Elapsed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // A tenant that is not soft-deleted cannot be erased (tenant-state 409), even
        // with force - the status check precedes the retention check.
        var active = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var eraseActive = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{active.TenantId}/erase", admin.Token, new { force = true }, cancellationToken);
        eraseActive.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(eraseActive, cancellationToken)).ShouldBe("starter:tenant-state-conflict");

        // Soft-deleted but within the window: force:false is refused (retention 409),
        // force:true succeeds (the documented break-glass).
        var forced = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await SoftDeleteAsync(admin.Token, forced.TenantId, cancellationToken);
        var withinWindow = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{forced.TenantId}/erase", admin.Token, new { force = false }, cancellationToken);
        withinWindow.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await ProblemTypeAsync(withinWindow, cancellationToken)).ShouldBe("starter:retention-not-elapsed");
        var forcedErase = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{forced.TenantId}/erase", admin.Token, new { force = true }, cancellationToken);
        forcedErase.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Soft-deleted and past the window (backdate deleted_at, the equivalent of
        // advancing the clock): force:false succeeds.
        var elapsed = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await SoftDeleteAsync(admin.Token, elapsed.TenantId, cancellationToken);
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update tenancy.tenants set deleted_at = now() - interval '31 days' where id = @t",
            cancellationToken,
            ("t", elapsed.TenantId));
        var elapsedErase = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{elapsed.TenantId}/erase", admin.Token, new { force = false }, cancellationToken);
        elapsedErase.StatusCode.ShouldBe(HttpStatusCode.OK);

        // A second erase of an already-gone tenant is a 404 (the row is gone).
        var again = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{elapsed.TenantId}/erase", admin.Token, new { force = true }, cancellationToken);
        again.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // A never-existed tenant is a 404.
        var missing = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{Guid.CreateVersion7()}/erase", admin.Token, new { force = true }, cancellationToken);
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Reactivate_RestoresSoftDeletedTenant_AndClearsDeletedAt()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var tenant = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await SoftDeleteAsync(admin.Token, tenant.TenantId, cancellationToken);
        (await StatusAsync(tenant.TenantId, cancellationToken)).ShouldBe("deleted");
        (await DeletedAtIsSetAsync(tenant.TenantId, cancellationToken)).ShouldBeTrue();

        // The widened reactivate accepts a `deleted` source and clears deleted_at.
        var reactivate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenant.TenantId}/reactivate", admin.Token, new { }, cancellationToken);
        reactivate.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await StatusAsync(tenant.TenantId, cancellationToken)).ShouldBe("active");
        (await DeletedAtIsSetAsync(tenant.TenantId, cancellationToken)).ShouldBeFalse();
    }

    [Fact]
    public async Task SelfServeExport_ReturnsBundle_ExcludesSecrets_IsGated_AndEmitsAuditedEvent()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await SeedTenantAsync(owner, cancellationToken);

        var response = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/export", owner.Token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var raw = await response.Content.ReadAsStringAsync(cancellationToken);

        using (var doc = JsonDocument.Parse(raw))
        {
            var root = doc.RootElement;
            root.GetProperty("formatVersion").GetInt32().ShouldBe(1);
            root.GetProperty("tenantId").GetGuid().ShouldBe(owner.TenantId);
            root.TryGetProperty("generatedAt", out _).ShouldBeTrue();

            var sections = root.GetProperty("sections");
            // A representative spread of the expected sections across all three modules.
            foreach (var section in new[]
                     {
                         "tenant", "memberships", "workspaces", "teams", "roles", "invitations",
                         "serviceAccounts", "notes", "auditLog", "webhookEndpoints", "usageCounters",
                         "featureFlagOverrides",
                     })
            {
                sections.TryGetProperty(section, out _).ShouldBeTrue($"the bundle must carry the '{section}' section");
            }

            // The service-account and webhook-endpoint sections are populated, so their
            // secret-exclusion is a real assertion, not a vacuous one.
            sections.GetProperty("serviceAccounts").GetArrayLength().ShouldBeGreaterThan(0);
            sections.GetProperty("webhookEndpoints").GetArrayLength().ShouldBeGreaterThan(0);
        }

        // The secret columns never appear in the bundle - neither the seeded secret
        // values nor the JSON field names a leak would produce.
        raw.ShouldNotContain(KeyHashSentinel(owner.TenantId));
        raw.ShouldNotContain(WebhookSecretSentinel(owner.TenantId));
        raw.ShouldNotContain("keyHash");
        raw.ShouldNotContain("signingSecretEncrypted");

        // The export emits the audited, webhook-deliverable event on the tenant spine.
        await WaitForTenantAuditAsync(owner.Token, "tenancy.tenant.data_exported", cancellationToken);

        // A plain member lacks data:export -> 403 permission-required.
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var refused = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/export", member.Token, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemTypeAsync(refused, cancellationToken)).ShouldBe("starter:permission-required");
    }

    [Fact]
    public async Task SensitiveColumns_NeverLeak_InTheExportBundle_OrTheOperatorSnapshot()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // The completeness mechanism is real (not vacuous): reflection over the
        // ITenantOwned types finds the [Sensitive] columns - the three known today.
        var assemblies = fixture.Factory.Services.GetServices<ITenantErasureContributor>()
            .Select(contributor => contributor.GetType().Assembly)
            .Append(typeof(ITenantErasureContributor).Assembly);
        var sensitive = SensitiveColumns.From(assemblies);
        sensitive.ShouldNotBeEmpty("the [Sensitive] reflection scan must find the secret columns, or it is vacuous");
        sensitive.ShouldContain("key_hash");
        sensitive.ShouldContain("signing_secret_encrypted");
        sensitive.ShouldContain("client_secret_encrypted");

        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await SeedTenantAsync(owner, cancellationToken);

        var keyHash = KeyHashSentinel(owner.TenantId);
        var webhookSecret = WebhookSecretSentinel(owner.TenantId);
        var ssoSecret = SsoClientSecretSentinel(owner.TenantId);

        // The export bundle carries the shaped sections but never the secret values.
        var export = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/export", owner.Token, cancellationToken);
        export.StatusCode.ShouldBe(HttpStatusCode.OK);
        var bundle = await export.Content.ReadAsStringAsync(cancellationToken);
        bundle.ShouldNotContain(keyHash);
        bundle.ShouldNotContain(webhookSecret);
        bundle.ShouldNotContain(ssoSecret);

        // The operator snapshot captures the raw rows (secret columns present but
        // REDACTED), never the secret values.
        await SoftDeleteAsync(admin.Token, owner.TenantId, cancellationToken);
        var erase = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{owner.TenantId}/erase", admin.Token, new { force = true }, cancellationToken);
        erase.StatusCode.ShouldBe(HttpStatusCode.OK);
        var snapshot = await erase.Content.ReadAsStringAsync(cancellationToken);

        snapshot.ShouldNotContain(keyHash);
        snapshot.ShouldNotContain(webhookSecret);
        snapshot.ShouldNotContain(ssoSecret);
        // The snapshot did capture those tables and redacted the secret columns by name.
        snapshot.ShouldContain("service_accounts");
        snapshot.ShouldContain("webhook_endpoints");
        snapshot.ShouldContain("sso_configs");
        snapshot.ShouldContain("[REDACTED]");
    }

    // --- seeding ---------------------------------------------------------

    // Populates a tenant with rows across the whole tenant-owned surface: memberships
    // (from signup), a workspace, a team + member, a custom role + permission +
    // assignment, a pending invitation, and a note (endpoints), plus a service account,
    // a webhook endpoint, a webhook delivery, a usage counter, and a feature-flag
    // override (direct SQL - the last five have no simple happy-path seed here). The
    // two secret columns carry per-tenant sentinels so leaks are detectable.
    private async Task SeedTenantAsync(OwnerContext owner, CancellationToken cancellationToken)
    {
        await TenantWorkflow.CreateWorkspaceAsync(fixture, owner.Token, TenantWorkflow.FreshSlug(), "Workspace", cancellationToken);

        var teamId = await TenantWorkflow.CreateTeamAsync(fixture, owner.Token, TenantWorkflow.FreshSlug(), "Team", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, owner.UserId, cancellationToken);

        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "seed-role", NotesReadOnly, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, owner.UserId, cancellationToken);

        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email = TenantWorkflow.FreshEmail("seed-invite"), role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var note = await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Seed note", cancellationToken);
        note.StatusCode.ShouldBe(HttpStatusCode.Created);

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into tenancy.service_accounts "
            + "(id, tenant_id, name, key_hash, key_prefix, created_by, created_at) "
            + "values (@id, @t, 'seed-sa', @hash, 'sk_seed', @u, now())",
            cancellationToken,
            ("id", Guid.CreateVersion7()),
            ("t", owner.TenantId),
            ("hash", KeyHashSentinel(owner.TenantId)),
            ("u", owner.UserId));

        var endpointId = Guid.CreateVersion7();
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into platform.webhook_endpoints "
            + "(id, tenant_id, url, description, event_types, signing_secret_encrypted, secret_prefix, created_by, created_at, updated_at) "
            // A non-matching event_types subscription (NOT the empty all-events array),
            // so the seeded events never fan out to this endpoint - keeps the delivery
            // pipeline idle and the per-tenant counts deterministic.
            + "values (@id, @t, 'https://receiver.example/hook', 'seed', '{seed.none}'::text[], @secret, 'whsec_seed', @u, now(), now())",
            cancellationToken,
            ("id", endpointId),
            ("t", owner.TenantId),
            ("secret", WebhookSecretSentinel(owner.TenantId)),
            ("u", owner.UserId));

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into platform.webhook_deliveries "
            + "(id, tenant_id, endpoint_id, event_id, event_type, payload, status, attempts, next_attempt_at, created_at) "
            + "values (@id, @t, @eid, @evid, 'seed.event', '{}'::jsonb, 'pending', 0, now(), now())",
            cancellationToken,
            ("id", Guid.CreateVersion7()),
            ("t", owner.TenantId),
            ("eid", endpointId),
            ("evid", Guid.CreateVersion7()));

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into platform.usage_counters (tenant_id, metric, period_start, used, updated_at) "
            + "values (@t, 'seed_metric', date '2026-07-01', 3, now())",
            cancellationToken,
            ("t", owner.TenantId));

        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into platform.feature_flag_overrides "
            + "(id, tenant_id, flag_key, scope_type, scope_id, enabled, set_by, updated_at) "
            + "values (@id, @t, 'seed_flag', 'tenant', null, true, @u, now())",
            cancellationToken,
            ("id", Guid.CreateVersion7()),
            ("t", owner.TenantId),
            ("u", owner.UserId));

        // A tenancy.sso_configs row whose client_secret_encrypted is the third
        // [Sensitive] column: seed a per-tenant sentinel, DataProtection-encrypted
        // through the host's own provider (purpose "identity.sso.client-secret.v1"),
        // so a leak of the plaintext into the export bundle or the operator snapshot
        // is detectable.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into tenancy.sso_configs "
            + "(tenant_id, issuer, client_id, client_secret_encrypted, enabled, created_at, updated_at) "
            + "values (@t, 'https://idp.seed.example', 'seed-client', @secret, true, now(), now())",
            cancellationToken,
            ("t", owner.TenantId),
            ("secret", EncryptSsoSecret(SsoClientSecretSentinel(owner.TenantId))));
    }

    // --- helpers ---------------------------------------------------------

    private static string KeyHashSentinel(Guid tenantId) => $"SENTINEL_KEYHASH_{tenantId:N}";

    private static string WebhookSecretSentinel(Guid tenantId) => $"SENTINEL_WEBHOOKSECRET_{tenantId:N}";

    private static string SsoClientSecretSentinel(Guid tenantId) => $"SENTINEL_SSOSECRET_{tenantId:N}";

    /// <summary>
    /// Encrypts an SSO client-secret sentinel with the host's own DataProtection
    /// provider (purpose "identity.sso.client-secret.v1"), the same shape the admin
    /// config-save path uses, so the stored ciphertext is what the [Sensitive]
    /// redaction must keep out of both artifacts.
    /// </summary>
    private string EncryptSsoSecret(string plaintext)
    {
        using var scope = fixture.Factory.Services.CreateScope();
        var provider = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        return provider.CreateProtector("identity.sso.client-secret.v1").Protect(plaintext);
    }

    private List<TenantTable> DeclaredTables() =>
        fixture.Factory.Services.GetServices<ITenantErasureContributor>()
            .SelectMany(contributor => contributor.Tables)
            .ToList();

    private static IEnumerable<TenantTable> RepresentativeTables(IEnumerable<TenantTable> tables)
    {
        var wanted = new HashSet<string>(StringComparer.Ordinal)
        {
            "tenancy.memberships",
            "tenancy.workspaces",
            "sample.notes",
            "tenancy.service_accounts",
            "platform.webhook_endpoints",
            "platform.usage_counters",
            "platform.feature_flag_overrides",
            "platform.domain_events",
            "tenancy.tenants",
        };
        return tables.Where(table => wanted.Contains(table.Table));
    }

    private Task<long> CountAsync(TenantTable table, Guid tenantId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            $"select count(*) from {table.Table} where {table.KeyColumn} = @t",
            cancellationToken,
            ("t", tenantId));

    private Task<long> UnrevokedSessionsAsync(Guid tenantId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.sessions where tenant_id = @t and revoked_at is null",
            cancellationToken,
            ("t", tenantId));

    private async Task SoftDeleteAsync(string adminToken, Guid tenantId, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantId}/delete", adminToken, new { }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task<string> StatusAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new Npgsql.NpgsqlCommand(
            "select status from tenancy.tenants where id = @t", connection);
        command.Parameters.AddWithValue("t", tenantId);
        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<bool> DeletedAtIsSetAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new Npgsql.NpgsqlCommand(
            "select deleted_at from tenancy.tenants where id = @t", connection);
        command.Parameters.AddWithValue("t", tenantId);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is not (null or DBNull);
    }

    private async Task WaitForQuiescentAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var pending = await PlatformWorkflow.CountAsync(
                fixture,
                "select count(*) from platform.outbox "
                + "where tenant_id = @t and delivered_at is null and poisoned_at is null",
                cancellationToken,
                ("t", tenantId));
            if (pending == 0)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"Tenant {tenantId} outbox did not drain within the deadline.");
    }

    private async Task WaitForTenantAuditAsync(string token, string action, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(
                fixture, $"/api/v1/tenant/audit?action={action}", token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            if (doc.RootElement.GetProperty("items").GetArrayLength() > 0)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No '{action}' audit row appeared within the deadline.");
    }

    private static async Task<string?> ProblemTypeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("type").GetString();
    }
}
