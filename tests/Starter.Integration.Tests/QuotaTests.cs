using System.Net;
using System.Text.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Usage quotas (quotas.md), driven through the real endpoints, the real seeded
/// plan catalogue, the real RLS-bound counter, and the real fail-open gates.
/// Proves: the metered ceiling reserves atomically within a period (200s to the
/// limit, then 429 with Retry-After and the starter:quota-exceeded slug); the
/// metered gate FAILS OPEN when the plan declares no limit (never 429, no counter
/// row written); the resource-count maxWorkspaces gate refuses at the ceiling (402
/// starter:resource-quota-reached) and fails open when absent; usage_counters is
/// RLS-isolated per tenant; and the usage report surfaces limits, metered usage,
/// and resource counts behind seats:read.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class QuotaTests(StarterAppFixture fixture)
{
    private const string DemoPath = "/api/v1/tenant/quota-demo";
    private const string UsagePath = "/api/v1/tenant/usage";
    private const string WorkspacesPath = "/api/v1/workspaces";

    private static readonly string[] MembersReadOnly = ["members:read"];

    // --- Metered ceiling within one period --------------------------------

    [Fact]
    public async Task MeteredQuota_ReservesToTheCeiling_ThenRefusesWith429AndRetryAfter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A plan with a small demo_calls budget (seatLimit is required at plan-write
        // time), assigned to the tenant.
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Metered", limits = new { seatLimit = 5, demo_calls = 2 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

        // Consume to the ceiling: two 200s (used 1, then 2).
        (await ConsumeDemoAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ConsumeDemoAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        // The next call breaches the ceiling: 429 with the metered slug and a
        // Retry-After header (the whole seconds until the period reset).
        var over = await ConsumeDemoAsync(owner.Token, cancellationToken);
        over.StatusCode.ShouldBe(HttpStatusCode.TooManyRequests);
        over.Headers.RetryAfter.ShouldNotBeNull();
        over.Headers.RetryAfter!.Delta.ShouldNotBeNull();
        over.Headers.RetryAfter.Delta!.Value.ShouldBeGreaterThan(TimeSpan.Zero);
        using var doc = await HttpTestHelpers.ReadJsonAsync(over, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:quota-exceeded");

        // The counter records exactly the ceiling - the blocked reserve consumed
        // nothing (the guard held), so it never oversells.
        (await MeteredUsedAsync(owner.TenantId, "demo_calls", cancellationToken)).ShouldBe(2);
    }

    // --- Fail open when unlimited -----------------------------------------

    [Fact]
    public async Task MeteredQuota_FailsOpen_WhenPlanDeclaresNoLimit_AndWritesNoCounterRow()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // The tenant stays on the seeded free plan (limits = { seatLimit: 5 }), which
        // declares no demo_calls limit. The metered gate is then a no-op: the route
        // never 429s, no matter how many times it is called.
        for (var i = 0; i < 5; i++)
        {
            (await ConsumeDemoAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        }

        // Fail-open is a TRUE no-op: an unlimited metric writes no counter row (no
        // write amplification), so there is nothing to prune later.
        (await CountCounterRowsAsync(owner.TenantId, "demo_calls", cancellationToken)).ShouldBe(0);
    }

    // --- Resource-count quota (maxWorkspaces) -----------------------------

    [Fact]
    public async Task ResourceQuota_MaxWorkspaces_RefusesAtCeiling_With402()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Two workspaces", limits = new { seatLimit = 5, maxWorkspaces = 2 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

        // Create to the ceiling: two workspaces succeed (count 0 < 2, then 1 < 2).
        (await CreateWorkspaceRawAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Created);
        (await CreateWorkspaceRawAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Created);

        // The third is refused: not temporal, so 402 (upgrade or delete something),
        // NOT the metered 429 - and with the DISTINCT resource-quota slug.
        var over = await CreateWorkspaceRawAsync(owner.Token, cancellationToken);
        over.StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);
        using var doc = await HttpTestHelpers.ReadJsonAsync(over, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:resource-quota-reached");
    }

    [Fact]
    public async Task ResourceQuota_MaxWorkspaces_FailsOpen_WhenPlanDeclaresNoLimit()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // The seeded free plan declares no maxWorkspaces, so the gate is a no-op:
        // creating past any small number keeps succeeding (unlimited, fail open).
        for (var i = 0; i < 4; i++)
        {
            (await CreateWorkspaceRawAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Created);
        }
    }

    // --- RLS isolation of usage_counters ----------------------------------

    [Fact]
    public async Task UsageCounters_AreRlsIsolated_PerTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Both tenants get a metered plan and each consumes once, so each has exactly
        // one counter row (one metric, one period).
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Metered", limits = new { seatLimit = 5, demo_calls = 10 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, tenantA.TenantId, planKey, cancellationToken);
        await AssignPlanAsync(admin.Token, tenantB.TenantId, planKey, cancellationToken);
        (await ConsumeDemoAsync(tenantA.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ConsumeDemoAsync(tenantB.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        // Raw SQL on the request role (RLS holds below EF): under A's GUC only A's
        // row is visible, and B's row is invisible even asking for it directly.
        (await CountUsageUnderGucAsync(guc: tenantA.TenantId, cancellationToken)).ShouldBe(1);
        (await CountUsageForTenantUnderGucAsync(
            guc: tenantA.TenantId, whereTenant: tenantB.TenantId, cancellationToken)).ShouldBe(0);
        (await CountUsageUnderGucAsync(guc: tenantB.TenantId, cancellationToken)).ShouldBe(1);
        // Absent GUC -> zero (fail closed: current_setting is NULL, the policy matches
        // nothing, and the nullif form never casts an empty string to uuid).
        (await CountUsageUnderGucAsync(guc: null, cancellationToken)).ShouldBe(0);
    }

    // --- Usage report -----------------------------------------------------

    [Fact]
    public async Task UsageReport_SurfacesLimitsMeteredAndResources_BehindSeatsRead()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Reported", limits = new { seatLimit = 5, demo_calls = 10 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

        // Consume the metered metric twice and hold one workspace, so the report has
        // real numbers to show.
        (await ConsumeDemoAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ConsumeDemoAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await CreateWorkspaceRawAsync(owner.Token, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Created);

        var report = await TenantWorkflow.GetAsync(fixture, UsagePath, owner.Token, cancellationToken);
        report.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(report, cancellationToken);
        var root = doc.RootElement;

        // limits: the plan's declared numeric limits, verbatim.
        root.GetProperty("limits").GetProperty("seatLimit").GetInt32().ShouldBe(5);
        root.GetProperty("limits").GetProperty("demo_calls").GetInt32().ShouldBe(10);

        // metered: the demo_calls metric reports its current-period used, limit, and reset.
        var metered = root.GetProperty("metered");
        var demo = FindByMetric(metered, "demo_calls");
        demo.GetProperty("used").GetInt64().ShouldBe(2);
        demo.GetProperty("limit").GetInt32().ShouldBe(10);
        demo.GetProperty("resetAt").GetDateTimeOffset().ShouldBeGreaterThan(DateTimeOffset.UnixEpoch);

        // metered lists the code-side known-metered set ONLY: the resource limit
        // seatLimit (in limits and under resources) must NOT appear here, even though
        // the plan declares it. Metered is not "every plan-limit key".
        HasMetric(metered, "demo_calls").ShouldBeTrue();
        HasMetric(metered, "seatLimit").ShouldBeFalse();

        // resources: the workspace and seat gauges (current count vs plan limit).
        var workspaces = FindByMetric(root.GetProperty("resources"), "workspaces");
        workspaces.GetProperty("used").GetInt64().ShouldBe(1);
        workspaces.GetProperty("limit").ValueKind.ShouldBe(JsonValueKind.Null); // free of a maxWorkspaces cap
        var seats = FindByMetric(root.GetProperty("resources"), "seats");
        seats.GetProperty("used").GetInt64().ShouldBe(1); // the owner
        seats.GetProperty("limit").GetInt32().ShouldBe(5);

        // Gated by seats:read: a service account whose only grant is members:read
        // (never seats:read) is refused at the gate, before the report runs.
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "reader", MembersReadOnly, cancellationToken);
        var readerKey = await CreateServiceAccountKeyAsync(owner.Token, roleId, cancellationToken);
        var refused = await TenantWorkflow.GetAsync(fixture, UsagePath, readerKey, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var refusedDoc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken);
        refusedDoc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    // --- helpers ----------------------------------------------------------

    private static string FreshPlanKey() => $"plan-{Guid.NewGuid():N}";

    private static JsonElement FindByMetric(JsonElement array, string metric)
    {
        foreach (var item in array.EnumerateArray())
        {
            if (item.GetProperty("metric").GetString() == metric)
            {
                return item;
            }
        }

        throw new InvalidOperationException($"No usage item for metric '{metric}'.");
    }

    private static bool HasMetric(JsonElement array, string metric)
    {
        foreach (var item in array.EnumerateArray())
        {
            if (item.GetProperty("metric").GetString() == metric)
            {
                return true;
            }
        }

        return false;
    }

    private Task<HttpResponseMessage> ConsumeDemoAsync(string token, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(fixture, DemoPath, token, new { }, cancellationToken);

    private Task<HttpResponseMessage> CreateWorkspaceRawAsync(string token, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(
            fixture, WorkspacesPath, token, new { slug = TenantWorkflow.FreshSlug(), name = "WS" }, cancellationToken);

    private async Task CreatePlanAsync(string adminToken, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(fixture, "/api/v1/platform/plans", adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task AssignPlanAsync(string adminToken, Guid tenantId, string planKey, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantId}/plan", adminToken, new { plan = planKey }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task<string> CreateServiceAccountKeyAsync(
        string ownerToken, Guid roleId, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/service-accounts", ownerToken, new { name = "reader-bot", roleId }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("key").GetString()!;
    }

    // The current-period used for a tenant/metric, read on the admin connection (bypasses RLS).
    private async Task<long> MeteredUsedAsync(Guid tenantId, string metric, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select coalesce(max(used), 0) from platform.usage_counters where tenant_id = @tenant and metric = @metric",
            connection);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("metric", metric);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<long> CountCounterRowsAsync(Guid tenantId, string metric, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select count(*) from platform.usage_counters where tenant_id = @tenant and metric = @metric",
            connection);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("metric", metric);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<long> CountUsageUnderGucAsync(Guid? guc, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.RequestDataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        if (guc is Guid tenant)
        {
            await SetTenantAsync(connection, transaction, tenant, cancellationToken);
        }

        await using var command = new NpgsqlCommand(
            "select count(*) from platform.usage_counters", connection, transaction);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<long> CountUsageForTenantUnderGucAsync(
        Guid guc, Guid whereTenant, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.RequestDataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, guc, cancellationToken);

        await using var command = new NpgsqlCommand(
            "select count(*) from platform.usage_counters where tenant_id = @tenant", connection, transaction);
        command.Parameters.AddWithValue("tenant", whereTenant);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task SetTenantAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid tenant, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select set_config('app.current_tenant', @tenant, true)", connection, transaction);
        command.Parameters.AddWithValue("tenant", tenant.ToString());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
