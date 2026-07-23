namespace Starter.Platform.Auth;

/// <summary>
/// The narrow seam the tid-token mint uses to read a tenant's session-lifetime
/// override (role-templates-and-policy-defaults.md section 5), declared in the
/// platform so the Identity module - which owns the tid mint
/// (<c>SelectTenantHandler</c>, <c>RefreshHandler</c>) - never references the
/// Tenancy module or its <c>tenancy.tenants</c> table (the module-boundary arch
/// test forbids it). This mirrors the existing <see cref="ITenantRoleReader"/> /
/// <see cref="IPermissionResolver"/> ports: the Tenancy module implements it and
/// the composition root bridges the port to that implementation, so Identity
/// depends on the port and there is one lookup with no drift.
/// <para>
/// The effective tid-token lifetime is <c>min(platform default, tenant override)</c>
/// (a tenant may TIGHTEN, never loosen). This reader returns only the tenant's own
/// override (or null when it has set none); the access-token issuer applies the
/// platform default and the min.
/// </para>
/// </summary>
public interface ITenantSessionPolicyReader
{
    /// <summary>
    /// The tenant's <c>session_max_seconds</c> override, or null when the tenant has
    /// set none (it inherits the platform default). Read for a NAMED tenant the
    /// caller may not yet hold a tid for (select-tenant) or that is carried on a
    /// refresh token (refresh), so it is not bound to a request-scoped active tenant.
    /// A missing tenant resolves to null (inherit the platform default).
    /// </summary>
    Task<int?> GetSessionMaxSecondsAsync(Guid tenantId, CancellationToken cancellationToken);
}
