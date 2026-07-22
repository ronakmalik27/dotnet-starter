namespace Starter.Platform.Data;

/// <summary>
/// A platform.feature_flags row: one operator-owned catalogue entry
/// (feature-flags.md section 2). A flag names an in-progress or gated capability -
/// a rollout, a kill switch, a per-tenant beta - NOT a commercial tier. The
/// catalogue is global (no <c>tenant_id</c>), like <c>platform.plans</c> and the
/// permission catalogue, so this is a no-RLS platform table read on the request
/// path (the evaluator) and written only on the bypass path (the super-admin
/// plane); the request role's write is REVOKEd at boot.
/// <para>
/// Feature flags FAIL CLOSED, the deliberate inversion of entitlements
/// (feature-flags.md section 1): the evaluator returns OFF for a missing row
/// (<see cref="FeatureFlagRow"/> null) or an archived one (<see cref="ArchivedAt"/>
/// set), never ON. An archived flag also disappears from the tenant surface.
/// </para>
/// </summary>
internal sealed class FeatureFlagRow
{
    /// <summary>Primary key; the flag identifier code checks against.</summary>
    public required string Key { get; init; }

    /// <summary>What the flag controls.</summary>
    public required string Description { get; init; }

    /// <summary>The global default when there is no rollout and no override.</summary>
    public required bool DefaultEnabled { get; init; }

    /// <summary>0..100; when set, overrides <see cref="DefaultEnabled"/> via the deterministic bucket. NULL = use <see cref="DefaultEnabled"/>.</summary>
    public int? RolloutPercentage { get; init; }

    /// <summary>May a tenant admin set an override for this flag (feature-flags.md section 5).</summary>
    public required bool TenantOverridable { get; init; }

    /// <summary>When set, the flag is archived: it resolves OFF and is hidden from the tenant surface.</summary>
    public DateTimeOffset? ArchivedAt { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}
