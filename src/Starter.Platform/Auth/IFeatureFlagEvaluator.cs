namespace Starter.Platform.Auth;

/// <summary>
/// Resolves a feature flag's value for the ACTIVE tenant (feature-flags.md section
/// 3): a Platform service on the request path. It reads the no-RLS
/// <c>platform.feature_flags</c> catalogue and the RLS-scoped
/// <c>platform.feature_flag_overrides</c> through the request-scoped platform
/// context in one read transaction (so the tenant GUC is set for the override read),
/// never the bypass data source.
/// <para>
/// Feature flags FAIL CLOSED (feature-flags.md section 1), the opposite of
/// entitlements: an unknown or archived flag resolves OFF, never ON. Resolution is
/// most-specific-wins: a WORKSPACE override beats a TENANT override beats the global
/// default (a fixed on/off, or a deterministic <see cref="FeatureFlagBucket"/>
/// percentage rollout). Resolution is cached per request on <c>(flagKey, workspaceId)</c>.
/// </para>
/// </summary>
public interface IFeatureFlagEvaluator
{
    /// <summary>
    /// True when <paramref name="flagKey"/> is ON for the active tenant (and, when
    /// given, <paramref name="workspaceId"/>). An unknown or archived flag is OFF
    /// (fail closed).
    /// </summary>
    Task<bool> IsEnabledAsync(
        string flagKey, Guid? workspaceId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves every non-archived flag in one pass over the catalogue and the
    /// tenant's overrides - the batch a client bootstrap uses to hydrate the UI.
    /// </summary>
    Task<IReadOnlyDictionary<string, bool>> EvaluateAllAsync(
        Guid? workspaceId, CancellationToken cancellationToken);
}
