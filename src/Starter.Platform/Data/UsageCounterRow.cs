using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// One metered-quota counter row (quotas.md section 2): the consumption of a
/// single metric by a single tenant over a single billing period. Tenant-owned and
/// RLS-enforced (the standard <c>tenant_isolation</c> policy on
/// <c>platform.usage_counters</c>), it is a normal request/consumer-path table: a
/// tenant's own request increments its own counter under row-level security. The
/// composite key <c>(tenant_id, metric, period_start)</c> is the upsert conflict
/// target, and <c>used</c> is a <c>bigint</c> so a high-volume metric cannot overflow.
/// Resource-count quotas need no row - they count the resource's own rows.
/// </summary>
internal sealed class UsageCounterRow : ITenantOwned
{
    /// <summary>The owning tenant (the RLS discriminator), stamped from context on write.</summary>
    public Guid TenantId { get; set; }

    /// <summary>The metered metric key; matches a plan <c>limits</c> key.</summary>
    public string Metric { get; set; } = string.Empty;

    /// <summary>The UTC first-of-month anchor of the billing period.</summary>
    public DateOnly PeriodStart { get; set; }

    /// <summary>Consumption in this period.</summary>
    public long Used { get; set; }

    /// <summary>The last increment.</summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
