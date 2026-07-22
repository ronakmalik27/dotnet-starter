using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Feature flags (feature-flags.md section 9), driven through the real endpoints, the
/// real seeded-empty catalogue, and the real fail-closed evaluator. Proves: unknown
/// and archived flags fail CLOSED (RequireFeatureFlag 404); resolution precedence
/// (workspace &gt; tenant &gt; default) and fallback on clear; deterministic rollout
/// (stable across calls, two tenants on opposite sides, raising the percent never
/// evicts an in-tenant); RLS isolation of overrides; the tenant_overridable gate
/// (flag_not_overridable, 403); super-admin-only catalogue CRUD and the
/// feature-flags:manage gate on the tenant surface; and that catalogue edits and
/// override changes are audited.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class FeatureFlagsTests(StarterAppFixture fixture)
{
    private const string TenantFlagsPath = "/api/v1/tenant/feature-flags";
    private const string PlatformFlagsPath = "/api/v1/platform/feature-flags";
    private const string GateDemoPath = "/api/v1/tenant/feature-flag-gate-demo";

    // --- Fail closed ------------------------------------------------------

    [Fact]
    public async Task FailClosed_UnknownAndArchivedFlag_Gate404()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // The gate-demo route is gated by RequireFeatureFlag("gate-demo"). Before the
        // flag exists, an UNKNOWN flag fails closed -> the feature looks absent (404).
        var unknown = await TenantWorkflow.GetAsync(fixture, GateDemoPath, owner.Token, cancellationToken);
        unknown.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(unknown, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:not-found");
        }

        // Turn the flag ON globally -> the gated route is now reachable (200).
        await CreateFlagAsync(
            admin.Token,
            new { key = "gate-demo", description = "Gate demo", defaultEnabled = true },
            cancellationToken);
        var on = await TenantWorkflow.GetAsync(fixture, GateDemoPath, owner.Token, cancellationToken);
        on.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Archive it -> an ARCHIVED flag fails closed too (404), the same as unknown.
        await PatchFlagAsync(admin.Token, "gate-demo", new { archived = true }, cancellationToken);
        var archived = await TenantWorkflow.GetAsync(fixture, GateDemoPath, owner.Token, cancellationToken);
        archived.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    // --- Resolution precedence --------------------------------------------

    [Fact]
    public async Task Resolution_WorkspaceBeatsTenantBeatsDefault_AndClearingFallsBack()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, TenantWorkflow.FreshSlug(), "WS", cancellationToken);

        // A tenant-overridable flag whose global default is OFF.
        var key = FreshFlagKey();
        await CreateFlagAsync(
            admin.Token,
            new { key, description = "Precedence", defaultEnabled = false, tenantOverridable = true },
            cancellationToken);

        // Default: OFF at both scopes.
        (await ResolvedAsync(owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(false);
        (await ResolvedAsync(owner.Token, key, workspaceId, cancellationToken)).ShouldBe(false);

        // Tenant override ON: both scopes ON (the workspace scope inherits the tenant
        // override when it has none of its own).
        await SetOverrideAsync(owner.Token, key, new { enabled = true, scopeType = "tenant" }, cancellationToken);
        (await ResolvedAsync(owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
        (await ResolvedAsync(owner.Token, key, workspaceId, cancellationToken)).ShouldBe(true);

        // Workspace override OFF: the workspace scope now resolves OFF (workspace beats
        // tenant), while the tenant scope stays ON.
        await SetOverrideAsync(
            owner.Token, key, new { enabled = false, scopeType = "workspace", scopeId = workspaceId }, cancellationToken);
        (await ResolvedAsync(owner.Token, key, workspaceId, cancellationToken)).ShouldBe(false);
        (await ResolvedAsync(owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);

        // Clear the workspace override: the workspace scope falls back to the tenant
        // override (ON).
        await ClearOverrideAsync(owner.Token, key, "workspace", workspaceId, cancellationToken);
        (await ResolvedAsync(owner.Token, key, workspaceId, cancellationToken)).ShouldBe(true);

        // Clear the tenant override: both scopes fall back to the global default (OFF).
        await ClearOverrideAsync(owner.Token, key, "tenant", scopeId: null, cancellationToken);
        (await ResolvedAsync(owner.Token, key, workspaceId, cancellationToken)).ShouldBe(false);
        (await ResolvedAsync(owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(false);
    }

    // --- Deterministic rollout --------------------------------------------

    [Fact]
    public async Task Rollout_IsDeterministic_StableAcrossCalls_AndMonotonic()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // The bucket is a stable hash of (flagKey, tenantId), so pick the key first,
        // then find two tenants that land on opposite sides of a chosen percent.
        var key = FreshFlagKey();
        var first = await SignupWithBucketAsync(key, cancellationToken);
        (OwnerContext Owner, int Bucket) second = default;
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var candidate = await SignupWithBucketAsync(key, cancellationToken);
            if (candidate.Bucket != first.Bucket)
            {
                second = candidate;
                break;
            }
        }

        second.Owner.ShouldNotBeNull("expected two tenants with distinct rollout buckets");

        var (lo, hi) = first.Bucket < second.Bucket ? (first, second) : (second, first);
        // ON iff bucket < percent, so at percent = hi.Bucket the lower tenant is IN
        // (lo.Bucket < hi.Bucket) and the higher is OUT (hi.Bucket is not < itself).
        var percent = hi.Bucket;

        await CreateFlagAsync(
            admin.Token,
            new { key, description = "Rollout", defaultEnabled = false, rolloutPercentage = percent },
            cancellationToken);

        (await ResolvedAsync(lo.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
        (await ResolvedAsync(hi.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(false);

        // Stable across repeated calls: the same tenant resolves the same value.
        (await ResolvedAsync(lo.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
        (await ResolvedAsync(hi.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(false);

        // Raising the percent never flips an in-tenant out: the lower tenant stays IN,
        // and the higher tenant is now admitted too.
        await PatchFlagAsync(admin.Token, key, new { rolloutPercentage = 100 }, cancellationToken);
        (await ResolvedAsync(lo.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
        (await ResolvedAsync(hi.Owner.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
    }

    // --- RLS isolation ----------------------------------------------------

    [Fact]
    public async Task Overrides_AreRlsIsolated_PerTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var key = FreshFlagKey();
        await CreateFlagAsync(
            admin.Token,
            new { key, description = "Isolated", defaultEnabled = false, tenantOverridable = true },
            cancellationToken);

        // Tenant A turns the flag on for itself.
        await SetOverrideAsync(tenantA.Token, key, new { enabled = true, scopeType = "tenant" }, cancellationToken);

        // A sees its own override (ON); B is unaffected and still resolves the default
        // (OFF) - A's override never crosses the tenant boundary.
        (await ResolvedAsync(tenantA.Token, key, workspaceId: null, cancellationToken)).ShouldBe(true);
        (await ResolvedAsync(tenantB.Token, key, workspaceId: null, cancellationToken)).ShouldBe(false);
    }

    // --- Overridable gate -------------------------------------------------

    [Fact]
    public async Task OverridableGate_AllowsOverridableFlag_RefusesOperatorHeldFlag()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var overridable = FreshFlagKey();
        await CreateFlagAsync(
            admin.Token,
            new { key = overridable, description = "Overridable", defaultEnabled = false, tenantOverridable = true },
            cancellationToken);
        var allowed = await SetOverrideRawAsync(
            owner.Token, overridable, new { enabled = true, scopeType = "tenant" }, cancellationToken);
        allowed.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // A flag the operator holds centrally (tenant_overridable = false) is refused.
        var held = FreshFlagKey();
        await CreateFlagAsync(
            admin.Token,
            new { key = held, description = "Operator held", defaultEnabled = false, tenantOverridable = false },
            cancellationToken);
        var refused = await SetOverrideRawAsync(
            owner.Token, held, new { enabled = true, scopeType = "tenant" }, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:flag-not-overridable");
    }

    // --- Super-admin only + feature-flags:manage --------------------------

    [Fact]
    public async Task CatalogueCrud_IsSuperAdminOnly_AndTenantSurfaceNeedsThePermission()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A tenant owner (not a platform admin) cannot touch the flag catalogue.
        var create = await TenantWorkflow.PostJsonAsync(
            fixture,
            PlatformFlagsPath,
            owner.Token,
            new { key = FreshFlagKey(), description = "Nope", defaultEnabled = true },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-admin-required");
        }

        // A plain member lacks feature-flags:manage, so the tenant override surface is
        // 403 permission-required (the owner, who has it, reaches it fine).
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var memberList = await TenantWorkflow.GetAsync(fixture, TenantFlagsPath, member.Token, cancellationToken);
        memberList.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(memberList, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }

        var ownerList = await TenantWorkflow.GetAsync(fixture, TenantFlagsPath, owner.Token, cancellationToken);
        ownerList.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // --- Audited ----------------------------------------------------------

    [Fact]
    public async Task CatalogueEdits_AreAuditedOnThePlatformLog_AndOverridesOnTheTenantLog()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var key = FreshFlagKey();
        await CreateFlagAsync(
            admin.Token,
            new { key, description = "Audited", defaultEnabled = false, tenantOverridable = true },
            cancellationToken);
        await PatchFlagAsync(admin.Token, key, new { description = "Audited (edited)" }, cancellationToken);

        // Flag create and update each land a platform-audit row synchronously.
        (await PlatformAuditCountAsync("platform.feature_flag.created", cancellationToken)).ShouldBeGreaterThanOrEqualTo(1);
        (await PlatformAuditCountAsync("platform.feature_flag.updated", cancellationToken)).ShouldBeGreaterThanOrEqualTo(1);

        // Setting a tenant override lands a tenant audit row (and is webhook-deliverable -
        // both ride the shared deliverable-event catalogue).
        await SetOverrideAsync(owner.Token, key, new { enabled = true, scopeType = "tenant" }, cancellationToken);
        await WaitForTenantAuditAsync(owner.Token, "tenancy.feature_flag.override_set", cancellationToken);
    }

    // --- helpers ----------------------------------------------------------

    private static string FreshFlagKey() => $"flag-{Guid.NewGuid():N}";

    private async Task<(OwnerContext Owner, int Bucket)> SignupWithBucketAsync(
        string flagKey, CancellationToken cancellationToken)
    {
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        return (owner, FeatureFlagBucket.Bucket(flagKey, owner.TenantId));
    }

    private async Task CreateFlagAsync(string adminToken, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(fixture, PlatformFlagsPath, adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task PatchFlagAsync(
        string adminToken, string key, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PatchJsonAsync(
            fixture, $"{PlatformFlagsPath}/{key}", adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private Task<HttpResponseMessage> SetOverrideRawAsync(
        string token, string key, object body, CancellationToken cancellationToken) =>
        TenantWorkflow.PutJsonAsync(fixture, $"{TenantFlagsPath}/{key}", token, body, cancellationToken);

    private async Task SetOverrideAsync(
        string token, string key, object body, CancellationToken cancellationToken)
    {
        var response = await SetOverrideRawAsync(token, key, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task ClearOverrideAsync(
        string token, string key, string scopeType, Guid? scopeId, CancellationToken cancellationToken)
    {
        var uri = $"{TenantFlagsPath}/{key}?scopeType={scopeType}";
        if (scopeId is Guid id)
        {
            uri += $"&scopeId={id}";
        }

        var response = await TenantWorkflow.DeleteAsync(fixture, uri, token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task<bool?> ResolvedAsync(
        string token, string key, Guid? workspaceId, CancellationToken cancellationToken)
    {
        var uri = workspaceId is Guid ws ? $"{TenantFlagsPath}?workspaceId={ws}" : TenantFlagsPath;
        var response = await TenantWorkflow.GetAsync(fixture, uri, token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (item.GetProperty("key").GetString() == key)
            {
                return item.GetProperty("enabled").GetBoolean();
            }
        }

        return null;
    }

    private Task<long> PlatformAuditCountAsync(string action, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.platform_audit_log where action = @action",
            cancellationToken,
            ("action", action));

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

        throw new InvalidOperationException($"No tenant audit row for '{action}' appeared within the deadline.");
    }
}
