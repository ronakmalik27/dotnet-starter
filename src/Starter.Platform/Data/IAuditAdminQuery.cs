using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The super-admin audit read (audit-log.md section 6): serves
/// <c>GET /api/v1/platform/audit</c> behind RequirePlatformAdmin. It reads on the
/// BYPASS path (a Platform reader type, which Platform may legitimately use), so
/// it can cross tenants: the compliance view. A tenant filter narrows the tenant
/// projection to one tenant; the platform selector returns the null-tenant
/// platform audit log instead.
/// </summary>
public interface IAuditAdminQuery
{
    /// <summary>
    /// Reads the tenant audit projection across tenants (or one tenant when
    /// <paramref name="tenantFilter"/> is set), newest first, keyset-paginated.
    /// </summary>
    Task<Result<AuditPage<AuditEntry>>> QueryTenantAsync(
        Guid? tenantFilter, AuditQueryFilter filter, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the null-tenant platform audit log (<c>scope=platform</c>), newest
    /// first, keyset-paginated.
    /// </summary>
    Task<Result<AuditPage<PlatformAuditEntry>>> QueryPlatformAsync(
        AuditQueryFilter filter, CancellationToken cancellationToken);
}
