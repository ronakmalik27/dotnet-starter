namespace Starter.Platform.Tenancy;

/// <summary>
/// The mutable, scoped <see cref="IWorkspaceContext"/> the <c>RequireWorkspace</c>
/// gate sets after validating the workspace exists in the active tenant. Internal
/// and its setter lives inside the platform: request code reads it through
/// <see cref="IWorkspaceContext"/> and never binds it. One instance per scope, so
/// a request carries at most one workspace with no cross-talk. Unresolved by
/// default, so a tenant-level request (no workspace route segment) leaves
/// <see cref="WorkspaceId"/> null and a write lands a tenant-level row.
/// </summary>
internal sealed class WorkspaceContext : IWorkspaceContext
{
    public Guid? WorkspaceId { get; private set; }

    public bool IsResolved { get; private set; }

    public bool IsArchived { get; private set; }

    /// <summary>
    /// Binds the active workspace (the resolvable case): a non-empty id resolves;
    /// the empty id does not (fail-closed). <paramref name="archived"/> carries the
    /// workspace's lifecycle state, so a mutating route can refuse an archived
    /// (read-only) workspace. Called by the gate only once the workspace has been
    /// confirmed to exist under the active tenant's RLS, so a bound workspace is
    /// always a real one the caller's tenant can see.
    /// </summary>
    public void Resolve(Guid workspaceId, bool archived)
    {
        if (workspaceId == Guid.Empty)
        {
            WorkspaceId = null;
            IsResolved = false;
            IsArchived = false;
            return;
        }

        WorkspaceId = workspaceId;
        IsResolved = true;
        IsArchived = archived;
    }
}
