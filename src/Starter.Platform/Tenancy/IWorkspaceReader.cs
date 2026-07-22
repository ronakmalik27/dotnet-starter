namespace Starter.Platform.Tenancy;

/// <summary>
/// The narrow seam the <c>RequireWorkspace</c> gate uses to confirm a workspace
/// exists in the ACTIVE tenant (multi-tenancy.md section 12), declared in the
/// platform so the platform never references the Tenancy module - the same port
/// pattern <see cref="ITenantRoleReader"/> and <see cref="ITenantContext"/> use.
/// The Tenancy module implements it as a request-path RLS read (a workspace row
/// is tenant-owned, so a workspaceId belonging to another tenant is simply
/// invisible and reads as "not found"), and the composition root bridges this
/// port to that implementation.
/// <para>
/// This is NOT the bypass path: it reads the active tenant's own rows bound by
/// row-level security, so it stays out of the bypass allowlist. It is
/// fail-closed: an unknown or cross-tenant workspace (or no resolved tenant)
/// reads as false, which the gate turns into 404 <c>starter:workspace-not-found</c>.
/// </para>
/// </summary>
public interface IWorkspaceReader
{
    /// <summary>
    /// Looks up <paramref name="workspaceId"/> under the active tenant's RLS in a
    /// single read. <c>Exists</c> is false for an unknown id, a cross-tenant id,
    /// or when no tenant is resolved (the gate turns that into 404). <c>Archived</c>
    /// carries the workspace lifecycle state so a mutating route can refuse an
    /// archived (read-only) workspace without a second round-trip; the module owns
    /// the status vocabulary and reports the archived/active decision as a bool,
    /// so the platform stays vocabulary-agnostic.
    /// </summary>
    Task<(bool Exists, bool Archived)> LookupWorkspaceAsync(Guid workspaceId, CancellationToken cancellationToken);
}
