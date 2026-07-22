using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// A platform.feature_flag_overrides row: a tenant's own override of a flag's
/// resolved value (feature-flags.md section 2), at tenant or workspace scope. Unlike
/// the global <see cref="FeatureFlagRow"/> catalogue, an override is tenant-owned and
/// RLS-enforced (<see cref="ITenantOwned"/> + FORCE row-level security + the standard
/// <c>tenant_isolation</c> policy), so a tenant admin only ever sees and sets its own
/// overrides and one tenant's override can never affect another's resolution.
/// <para>
/// A tenant admin may only override a flag the operator marked
/// <see cref="FeatureFlagRow.TenantOverridable"/>; an operator-held flag (a kill
/// switch or a not-yet-GA feature) is refused. The unique
/// <c>(tenant_id, flag_key, scope_type, scope_id)</c> index uses NULLS NOT DISTINCT,
/// so a tenant-scope override (<see cref="ScopeId"/> NULL) is unique per flag and a
/// PUT-as-upsert works even when <see cref="ScopeId"/> is NULL.
/// </para>
/// </summary>
internal sealed class FeatureFlagOverrideRow : ITenantOwned
{
    /// <summary>Primary key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The RLS discriminator, stamped from the tenant context on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The flag this overrides (the catalogue key).</summary>
    public required string FlagKey { get; init; }

    /// <summary><c>tenant</c> or <c>workspace</c>.</summary>
    public required string ScopeType { get; init; }

    /// <summary>The workspace id for a workspace override; NULL for tenant scope.</summary>
    public Guid? ScopeId { get; init; }

    /// <summary>The override value.</summary>
    public required bool Enabled { get; set; }

    /// <summary>The user who set the override.</summary>
    public required Guid SetBy { get; set; }

    /// <summary>When the override was last set or changed.</summary>
    public required DateTimeOffset UpdatedAt { get; set; }
}
