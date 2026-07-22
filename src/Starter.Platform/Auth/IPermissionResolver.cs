namespace Starter.Platform.Auth;

/// <summary>
/// The narrow seam the platform's tenant-aware authorization uses to read the
/// caller's EFFECTIVE permission set in the active tenant (multi-tenancy.md
/// section 13), declared in the platform so the platform never references the
/// Tenancy module - the same port pattern <see cref="ITenantRoleReader"/> uses.
/// The Tenancy module implements it as a request-path RLS read (the caller's
/// active membership plus their tenant-scope custom-role grants, all visible
/// only under the active tenant's GUC), and the composition root bridges this
/// port to that implementation, so there is one resolver and no drift.
/// <para>
/// This is deliberately NOT the bypass path: it reads the caller's own-tenant
/// rows bound by row-level security, so it stays out of the bypass allowlist.
/// It is fail-closed: a caller with no active membership in the active tenant
/// (or no resolved tenant) resolves to the empty set.
/// </para>
/// </summary>
public interface IPermissionResolver
{
    /// <summary>
    /// The caller's effective permissions in the active tenant at TENANT scope:
    /// the union of their active membership's system-role permissions and every
    /// tenant-scope custom-role grant they hold. Empty when they hold no active
    /// membership there. Resolution is per request and cached per request.
    /// </summary>
    Task<IReadOnlySet<string>> GetCallerPermissionsAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// The caller's effective permissions in the active tenant AT A WORKSPACE
    /// (multi-tenancy.md section 13): the tenant-scope set above PLUS every
    /// workspace-scope grant whose scope is exactly <paramref name="workspaceId"/>.
    /// Inheritance is downward only - a tenant-scope grant reaches every workspace,
    /// while a workspace-scope grant applies only in its own workspace and never
    /// confers anything tenant-wide. Same fail-closed, active-membership-only,
    /// request-path RLS discipline as the tenant-scope path; cached per request
    /// per workspace, so one request can resolve its tenant set and one workspace
    /// set without re-reading.
    /// </summary>
    Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid userId, Guid workspaceId, CancellationToken cancellationToken);
}
