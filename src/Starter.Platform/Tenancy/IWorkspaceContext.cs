namespace Starter.Platform.Tenancy;

/// <summary>
/// The active WORKSPACE for a unit of work, request-scoped and resolved from the
/// route (multi-tenancy.md section 12). Unlike <see cref="ITenantContext"/> a
/// workspace is NOT a database-enforced isolation boundary and never sets a GUC:
/// it is an authorization scope inside the tenant plus a nullable
/// <c>workspace_id</c> column on tenant-owned rows. A workspace-scoped endpoint
/// binds it (through the <c>RequireWorkspace</c> gate) after validating the
/// workspace exists in the active tenant; a tenant-level endpoint leaves it
/// unresolved, so a write stamps <see cref="WorkspaceId"/> = null (a tenant-level
/// row).
/// <para>
/// Read-only by contract, exactly like <see cref="ITenantContext"/>: request code
/// reads the resolved workspace through this interface and never widens it. The
/// workspace is per request, never in the access token (a signed-in user works
/// across many workspaces in one session), so nothing here is derived from a
/// claim.
/// </para>
/// </summary>
public interface IWorkspaceContext
{
    /// <summary>
    /// The active workspace id, or null when no workspace is in play (a
    /// tenant-level request). A tenant-owned write reads this to stamp its
    /// nullable <c>workspace_id</c>: null binds the row to the whole tenant, a
    /// set value binds it to that workspace.
    /// </summary>
    Guid? WorkspaceId { get; }

    /// <summary>
    /// True once a concrete workspace is bound (the request is workspace-scoped).
    /// A tenant-level request leaves this false and <see cref="WorkspaceId"/> null.
    /// </summary>
    bool IsResolved { get; }

    /// <summary>
    /// True when the bound workspace is archived (multi-tenancy.md section 20): its
    /// resources are read-only, so a mutating workspace-scoped route refuses it
    /// (409 <c>starter:workspace-archived</c>) while reads stay fully served. False
    /// when active or unresolved.
    /// </summary>
    bool IsArchived { get; }
}
