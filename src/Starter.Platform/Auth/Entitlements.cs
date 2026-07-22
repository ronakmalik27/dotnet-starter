namespace Starter.Platform.Auth;

/// <summary>
/// A tenant's resolved commercial entitlements (billing-and-entitlements.md
/// section 3): the feature set, the grantable-permission catalogue, and the
/// numeric limits its plan confers. This is a plain value object with no tenant
/// or plan identity - <see cref="IEntitlementSource"/> resolves a plan key into
/// one.
/// <para>
/// Entitlement checks FAIL OPEN, the deliberate inversion of every security gate
/// (billing-and-entitlements.md section 1): a commercial gate must never lock a
/// paying-by-default starter out of its own features. A null
/// <see cref="Features"/> or <see cref="GrantablePermissions"/> means the plan
/// restricts NOTHING (everything is allowed); a non-null set is CLOSED to exactly
/// that set (anything not listed is denied). So the unrestricted default (both
/// null) is a no-op filter until an operator deliberately publishes a restrictive
/// list.
/// </para>
/// </summary>
public sealed class Entitlements
{
    private static readonly IReadOnlyDictionary<string, int> NoLimits =
        new Dictionary<string, int>(StringComparer.Ordinal);

    /// <summary>
    /// The fail-open default: no plan, an unknown plan key, or a plan that
    /// restricts nothing. Every feature and every non-owner-reserved permission is
    /// allowed and there are no numeric limits.
    /// </summary>
    public static readonly Entitlements Unrestricted = new(features: null, grantablePermissions: null, NoLimits);

    public Entitlements(
        IReadOnlySet<string>? features,
        IReadOnlySet<string>? grantablePermissions,
        IReadOnlyDictionary<string, int> limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        Features = features;
        GrantablePermissions = grantablePermissions;
        Limits = limits;
    }

    /// <summary>The feature keys the plan INCLUDES, or null when the plan restricts no feature (unrestricted).</summary>
    public IReadOnlySet<string>? Features { get; }

    /// <summary>The RBAC permission atoms a custom role on this plan may hold, or null when unrestricted (section 4a).</summary>
    public IReadOnlySet<string>? GrantablePermissions { get; }

    /// <summary>The plan's numeric limits, e.g. <c>seatLimit</c> and <c>maxWorkspaces</c>.</summary>
    public IReadOnlyDictionary<string, int> Limits { get; }

    /// <summary>True when the plan includes <paramref name="feature"/> - unrestricted OR the set contains it (fail open).</summary>
    public bool HasFeature(string feature) => Features is null || Features.Contains(feature);

    /// <summary>True when a custom role on this plan may hold <paramref name="permission"/> - unrestricted OR the set contains it (fail open).</summary>
    public bool AllowsPermission(string permission) =>
        GrantablePermissions is null || GrantablePermissions.Contains(permission);

    /// <summary>The plan's limit for <paramref name="key"/>, or <paramref name="fallback"/> when the plan declares none.</summary>
    public int GetLimit(string key, int fallback) => Limits.TryGetValue(key, out var value) ? value : fallback;
}
