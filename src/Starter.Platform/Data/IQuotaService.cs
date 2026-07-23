namespace Starter.Platform.Data;

/// <summary>
/// The metered-quota counter mechanics (quotas.md section 4): a Platform service on
/// the request path that owns the atomic reserve on <c>platform.usage_counters</c>.
/// It resolves the request-scoped platform context (RLS-bound to the active tenant,
/// exactly like the entitlement source and feature-flag evaluator) and does NOT
/// resolve the plan - the caller passes the resolved limit in, so Platform stays
/// free of any Tenancy reference.
/// <para>
/// A quota is a COMMERCIAL gate, so it FAILS OPEN like an entitlement, not closed
/// like a security gate (section 1): an absent limit means the metric is unlimited
/// and the consume is a true no-op that writes nothing. Enforcement engages only
/// once an operator publishes a plan naming a finite limit for the metric. A limit
/// of <c>0</c> is deny-all (intended).
/// </para>
/// </summary>
public interface IQuotaService
{
    /// <summary>
    /// Consumes <paramref name="amount"/> of the metered <paramref name="metric"/>
    /// against <paramref name="limit"/> for the current period.
    /// <list type="bullet">
    ///   <item>A null <paramref name="limit"/> is unlimited: a no-op that writes
    ///   nothing and returns an allowed outcome with <c>used = 0</c>.</item>
    ///   <item>A non-null limit is HARD-enforced with an atomic guarded reserve: the
    ///   increment is applied only if it stays at or under the limit, so the reserve
    ///   cannot oversell (concurrent requests serialize on the row lock). An outcome
    ///   is allowed when the amount was consumed, denied when the guard blocked it
    ///   (nothing consumed; <c>used</c> is the current value).</item>
    /// </list>
    /// <paramref name="amount"/> MUST be positive.
    /// </summary>
    Task<QuotaOutcome> TryConsumeAsync(string metric, long amount, int? limit, CancellationToken cancellationToken);

    /// <summary>
    /// The current-period <c>used</c> for each requested metric (0 for a metric with
    /// no row yet), for the usage report. An RLS-scoped read; writes nothing.
    /// </summary>
    Task<IReadOnlyList<MeteredUsage>> GetUsageAsync(
        IReadOnlyCollection<string> metrics, CancellationToken cancellationToken);
}

/// <summary>The outcome of a metered consume: whether it was allowed, the resulting (or current) usage, the limit, and the period reset.</summary>
public sealed record QuotaOutcome(bool Allowed, long Used, int? Limit, DateTimeOffset ResetAt);

/// <summary>One metric's current-period consumption, for the usage report.</summary>
public sealed record MeteredUsage(string Metric, long Used);
