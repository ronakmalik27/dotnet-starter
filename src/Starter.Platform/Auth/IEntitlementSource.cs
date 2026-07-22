namespace Starter.Platform.Auth;

/// <summary>
/// Resolves a plan key into the plan's <see cref="Entitlements"/>
/// (billing-and-entitlements.md section 3). It loads the operator-owned
/// <c>platform.plans</c> catalogue - a global, no-RLS table - through the
/// request-scoped platform context, so it is ordinary request/consumer code and
/// never touches the bypass data source (the catalogue has no row-level security
/// to bypass).
/// <para>
/// An unknown or null plan key resolves to <see cref="Entitlements.Unrestricted"/>
/// (fail open, section 1): when billing is not configured every feature is
/// available, so the filter is a no-op until an operator deliberately defines a
/// restrictive plan. The catalogue is tiny and read per resolve, so a tightened
/// plan takes effect on the next request with no stale-cache window.
/// </para>
/// </summary>
public interface IEntitlementSource
{
    /// <summary>
    /// Resolves <paramref name="planKey"/> to its entitlements. A null, blank, or
    /// unknown key yields <see cref="Entitlements.Unrestricted"/>.
    /// </summary>
    Task<Entitlements> ResolveAsync(string? planKey, CancellationToken cancellationToken);
}
