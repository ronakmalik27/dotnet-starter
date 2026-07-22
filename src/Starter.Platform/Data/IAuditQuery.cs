using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The tenant-admin audit read (audit-log.md section 6): serves
/// <c>GET /api/v1/tenant/audit</c>. It reads the RLS-bound
/// <see cref="PlatformDbContext"/>, so results are scoped to the caller's tenant
/// automatically - there is no tenant id in the request. A Platform service (the
/// audit log lives in Platform next to the outbox it projects from), request-
/// scoped like every other RLS-bound read.
/// </summary>
public interface IAuditQuery
{
    /// <summary>
    /// Reads the caller's tenant audit log, newest first, keyset-paginated. A
    /// malformed cursor is a Validation failure (mapped to 422), never a throw.
    /// </summary>
    Task<Result<AuditPage<AuditEntry>>> QueryAsync(
        AuditQueryFilter filter, CancellationToken cancellationToken);
}
