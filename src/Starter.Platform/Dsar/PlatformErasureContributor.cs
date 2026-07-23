namespace Starter.Platform.Dsar;

/// <summary>
/// The Platform module's erasure declaration (data-export-and-erasure.md section 4):
/// the tenant-owned platform tables plus the tenant's rows on the event spine
/// (<c>domain_events</c> and any pending <c>outbox</c>), which carry tenant payloads.
/// <c>platform.platform_audit_log</c> is NOT tenant-owned (operator actions, retained
/// under legal basis) and is never listed - it is where the erasure records itself.
/// <c>platform.processed_events</c> has no tenant_id and is left in place (its orphaned
/// claim rows are harmless, no PII, no FK). Declaration only - this touches no bypass.
/// </summary>
internal sealed class PlatformErasureContributor : ITenantErasureContributor
{
    public IReadOnlyList<TenantTable> Tables { get; } =
    [
        new("platform.audit_log", "tenant_id"),
        new("platform.webhook_deliveries", "tenant_id"),
        new("platform.webhook_endpoints", "tenant_id"),
        new("platform.usage_counters", "tenant_id"),
        new("platform.feature_flag_overrides", "tenant_id"),
        // The event spine carries tenant payloads (section 4); the tenant-column
        // indexes added this increment keep the delete from a growing seq scan.
        new("platform.domain_events", "tenant_id"),
        new("platform.outbox", "tenant_id"),
    ];
}
