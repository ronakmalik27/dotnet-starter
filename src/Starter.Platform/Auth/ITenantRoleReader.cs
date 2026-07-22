namespace Starter.Platform.Auth;

/// <summary>
/// The narrow seam the platform's tenant-aware authorization needs to read the
/// caller's role in the active tenant, declared in the platform so the platform
/// never references the Tenancy module (the same port pattern
/// <see cref="ITenantProvisioningIdentity"/> uses for the Identity seam). The
/// Tenancy module implements it as a request-path RLS read - a membership is
/// visible only under its own tenant's GUC - and the composition root bridges
/// this port to that implementation, so there is one lookup and no drift.
/// <para>
/// This is deliberately NOT the bypass path: it reads the caller's own-tenant
/// membership bound by row-level security, so it stays out of the bypass
/// allowlist. A caller with no active membership in the active tenant resolves
/// to null.
/// </para>
/// </summary>
public interface ITenantRoleReader
{
    /// <summary>
    /// The caller's role in the active tenant, or null when they hold no active
    /// membership there (or no tenant is resolved). The active tenant is the one
    /// the request-scoped tenant context carries; the lookup is RLS-bound to it.
    /// </summary>
    Task<TenantRole?> GetCallerRoleAsync(Guid userId, CancellationToken cancellationToken);
}
