using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.workspaces row: a named scope WITHIN one tenant (multi-tenancy.md
/// sections 12, 17). A tenant has one or many; the count and the names are the
/// customer's. It is <see cref="ITenantOwned"/> in the ordinary way (a real
/// tenant_id column, the RLS discriminator and the query-filter key), so listing
/// workspaces is an ordinary tenant-scoped read and one tenant can never see
/// another's workspaces.
/// <para>
/// A workspace is deliberately NOT a second RLS GUC: it is an authorization scope
/// (section 12). Resources become workspace-scoped by carrying a nullable
/// workspace_id that references this row by value; the scoped-RBAC layer, not the
/// database, refuses a caller with no grant in the workspace. Slug is unique per
/// tenant (citext), mirroring tenancy.tenants.
/// </para>
/// </summary>
internal sealed class Workspace : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>Case-insensitive unique per tenant (citext), caller-supplied at create.</summary>
    public required string Slug { get; init; }

    /// <summary>The human-facing name. Editable.</summary>
    public required string Name { get; set; }

    /// <summary>One of active | archived (stored as a string). Editable via archive.</summary>
    public required string Status { get; set; }

    /// <summary>The user who created the workspace. A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>tenancy.workspaces.status values: the workspace lifecycle (section 20).</summary>
internal static class WorkspaceStatus
{
    public const string Active = "active";

    public const string Archived = "archived";
}
