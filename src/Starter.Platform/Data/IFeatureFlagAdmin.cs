using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The tenant feature-flag override control plane (feature-flags.md section 5), a
/// Platform-registered, RLS-bound service the Api endpoints call. It lives in
/// Platform (the feature does, next to the catalogue and the evaluator) so the Api
/// layer never touches the internal <c>PlatformDbContext</c> or the bypass path:
/// every override write runs on the active tenant under row-level security. It is
/// gated at the endpoint by <c>RequirePermission(feature-flags:manage)</c>.
/// <para>
/// A tenant admin can only set or clear an override for a flag the operator marked
/// <c>tenant_overridable</c>; an operator-held flag (a kill switch or a not-yet-GA
/// feature) is refused with <c>tenancy.flag_not_overridable</c>. Both set and clear
/// emit a tenant-scoped event (audited and webhook-deliverable).
/// </para>
/// </summary>
public interface IFeatureFlagAdmin
{
    /// <summary>
    /// Lists the tenant's resolved flags (feature-flags.md section 5): each
    /// non-archived catalogue flag with its description, its resolved value, and
    /// whether the tenant may override it. Resolution is at tenant scope by default;
    /// pass a <paramref name="workspaceId"/> to resolve at that workspace (a workspace
    /// override then wins over a tenant override), the view a client hydrating a
    /// specific workspace uses.
    /// </summary>
    Task<IReadOnlyList<ResolvedFeatureFlag>> ListResolvedAsync(
        Guid? workspaceId, CancellationToken cancellationToken);

    /// <summary>
    /// Sets (upserts) a tenant or workspace override for <paramref name="flagKey"/>.
    /// Refuses an unknown or archived flag (NotFound), a flag the operator did not
    /// mark overridable (<c>tenancy.flag_not_overridable</c>), and a malformed scope.
    /// Emits <c>tenancy.feature_flag.override_set</c>.
    /// </summary>
    Task<Result> SetOverrideAsync(
        Guid callerUserId,
        string flagKey,
        bool enabled,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Clears a tenant or workspace override for <paramref name="flagKey"/>, so the
    /// flag falls back to the layer below. Same refusals as
    /// <see cref="SetOverrideAsync"/>. Idempotent - clearing an absent override is a
    /// benign success. Emits <c>tenancy.feature_flag.override_cleared</c> when a row
    /// was removed.
    /// </summary>
    Task<Result> ClearOverrideAsync(
        Guid callerUserId,
        string flagKey,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken);
}

/// <summary>
/// A resolved flag as the tenant sees it (feature-flags.md section 5): the key, what
/// it controls, its resolved value at tenant scope, and whether the tenant may set an
/// override for it.
/// </summary>
public sealed record ResolvedFeatureFlag(string Key, string Description, bool Enabled, bool Overridable);
