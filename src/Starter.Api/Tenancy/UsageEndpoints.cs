using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the usage report (quotas.md section 7) and the metered-quota
/// gate DEMONSTRATION route (section 5). The report, GET /api/v1/tenant/usage, is
/// the standard usage dashboard: the plan's declared limits, the metered metrics'
/// current-period consumption, and the resource-count gauges - composed in the Api
/// layer from <see cref="ITenancyApi"/> (limits + resource counts) and
/// <see cref="IQuotaService"/> (metered usage), so neither service reaches across
/// the module boundary. It reuses the existing <c>seats:read</c> permission (usage
/// and seats are the same "what am I consuming vs my plan" question), so no new
/// permission atom.
/// <para>
/// The RequireQuota filter must run at map time, so like the feature-flag gate demo
/// (feature-flags.md section 4) a dedicated route <c>/api/v1/tenant/quota-demo</c>
/// gated by <c>RequireQuota("demo_calls")</c> maps ONLY when
/// <see cref="DemoConfigKey"/> is set - the integration-test host sets it; production
/// never maps it, so no live route carries a metered quota by default.
/// </para>
/// </summary>
public static class UsageEndpoints
{
    /// <summary>The shipped metered metric key (the demo route consumes it; the usage report always lists it).</summary>
    public const string DemoMetric = "demo_calls";

    /// <summary>The plan-limit key for the resource-count workspace gauge.</summary>
    public const string MaxWorkspacesLimit = "maxWorkspaces";

    /// <summary>
    /// The code-side set of METERED metric keys (quotas.md section 7). The plan
    /// <c>limits</c> map is a flat key-to-int and does NOT tag a key as metered vs
    /// resource, so the app decides which keys are metered: only these are windowed
    /// counters. <c>seatLimit</c> / <c>maxWorkspaces</c> are RESOURCE limits reported
    /// under <c>resources</c>, never here (they have no per-period counter, so a bare
    /// <c>used: 0</c> would teach a muddled model). Every limit still appears verbatim
    /// under <c>limits</c>. Today the only metered metric is the shipped
    /// <c>demo_calls</c>; a new metered metric is a new entry here plus a
    /// <c>RequireQuota</c> on its route.
    /// </summary>
    public static readonly IReadOnlyList<string> KnownMeteredMetrics = [DemoMetric];

    /// <summary>The config key that maps the metered-quota demonstration endpoint (test host only).</summary>
    public const string DemoConfigKey = "Quotas:DemoEnabled";

    public static IEndpointRouteBuilder MapUsageEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var tenant = app.MapGroup("/api/v1/tenant")
            .RequireTenant()
            .RequireAuthorization();

        // The usage report is a read: it reports usage, so it never carries
        // RequireQuota (which would consume a unit just to look). Reuses seats:read.
        tenant.MapGet("/usage", GetUsageAsync).RequirePermission(Permissions.SeatsRead);

        return app;
    }

    /// <summary>
    /// Maps the RequireQuota gate demonstration endpoint (quotas.md section 5).
    /// Registered ONLY when the caller opts in (the test host), so no live route is
    /// metered by default. Each call consumes one unit of the <c>demo_calls</c>
    /// metric; the gate returns 200 while under the plan's limit, and short-circuits
    /// 429 with a Retry-After header at the ceiling. Fails open when the plan
    /// declares no <c>demo_calls</c> limit (always 200, writes no counter row).
    /// </summary>
    public static IEndpointRouteBuilder MapQuotaDemoEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // POST: consuming a metered quota is a WRITE (it increments the counter).
        app.MapPost("/api/v1/tenant/quota-demo", QuotaDemoAsync)
            .RequireTenant()
            .RequireAuthorization()
            .RequireQuota(DemoMetric);

        return app;
    }

    private static async Task<IResult> GetUsageAsync(
        ITenancyApi tenancy,
        IQuotaService quotas,
        Clock clock,
        CancellationToken cancellationToken)
    {
        // Limits + the seat gauge, from the module (RLS-bound).
        var (seatLimit, activeMembers, _, limits) = await tenancy.GetSeatsAsync(cancellationToken);
        var workspaceCount = (await tenancy.ListWorkspacesAsync(cancellationToken)).Count;

        // Metered: the code-side KNOWN-METERED metrics only, NEVER the plan's limit
        // keys (section 7). The limits map does not tag a key as metered vs resource,
        // so resource limits like seatLimit / maxWorkspaces are reported under
        // resources, not here - listing them under metered with a bare used: 0 would
        // double-report them and teach a muddled model. A metric with a null limit is
        // unlimited and NOT metered (section 4's no-op), so its used is surfaced as
        // null ("not tracked"), never a bare 0. A metric with a limit reports its
        // current-period counter (0 for no row yet).
        var meteredMetrics = KnownMeteredMetrics;
        var usage = await quotas.GetUsageAsync(meteredMetrics, cancellationToken);
        var usedByMetric = usage.ToDictionary(item => item.Metric, item => item.Used, StringComparer.Ordinal);
        var resetAt = QuotaPeriod.ResetAt(clock.UtcNow);

        var metered = meteredMetrics
            .Select(metric =>
            {
                int? limit = limits.TryGetValue(metric, out var value) ? value : null;
                long? used = limit is null
                    ? null
                    : usedByMetric.TryGetValue(metric, out var counter) ? counter : 0;
                return new MeteredUsageItem(metric, used, limit, resetAt);
            })
            .ToList();

        int? maxWorkspaces = limits.TryGetValue(MaxWorkspacesLimit, out var max) ? max : null;
        var resources = new List<ResourceUsageItem>
        {
            new("workspaces", workspaceCount, maxWorkspaces),
            new("seats", activeMembers, seatLimit),
        };

        return Results.Ok(new UsageResponse(limits, metered, resources));
    }

    private static IResult QuotaDemoAsync() => Results.Ok(new QuotaDemoResponse(true));
}

/// <summary>
/// GET /api/v1/tenant/usage success body (quotas.md section 7): the plan's declared
/// limits verbatim, the metered metrics' current-period usage, and the
/// resource-count gauges.
/// </summary>
public sealed record UsageResponse(
    IReadOnlyDictionary<string, int> Limits,
    IReadOnlyList<MeteredUsageItem> Metered,
    IReadOnlyList<ResourceUsageItem> Resources);

/// <summary>
/// One metered metric in the usage report: the current-period <paramref name="Used"/>
/// (null = unlimited, "not tracked"), the <paramref name="Limit"/> (null =
/// unlimited), and the period <paramref name="ResetAt"/>. A consumer keys off
/// <c>Limit == null</c>.
/// </summary>
public sealed record MeteredUsageItem(string Metric, long? Used, int? Limit, DateTimeOffset ResetAt);

/// <summary>One resource-count gauge in the usage report: the current count vs the plan limit (null = unlimited).</summary>
public sealed record ResourceUsageItem(string Metric, long Used, int? Limit);

/// <summary>POST /api/v1/tenant/quota-demo success body (the metered-gate demonstration).</summary>
public sealed record QuotaDemoResponse(bool Ok);
