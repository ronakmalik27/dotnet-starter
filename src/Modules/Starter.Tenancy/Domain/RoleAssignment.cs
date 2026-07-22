using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.role_assignments row: a grant binding a CUSTOM role to a principal
/// at a scope (multi-tenancy.md sections 13, 17). Only custom roles are grantable
/// this way; a system role is conferred solely through
/// tenancy.memberships.role, so cross-cutting system power is never handed out
/// through a scoped grant. Tenant-owned, under the tenant RLS.
/// <para>
/// A grant is at tenant scope (scope_id null, applies tenant-wide) or at one
/// workspace (scope_id = the workspace). Only the user principal is supported;
/// the principal_type column is present for the forward-compatible team
/// increment. Uniqueness is a partial unique index per scope kind (one WHERE
/// scope_type = 'tenant', one for workspace scope including scope_id), because a
/// null scope_id would not collide under a plain unique constraint.
/// </para>
/// </summary>
internal sealed class RoleAssignment : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>One of user | team (stored as a string). Only user this increment.</summary>
    public required string PrincipalType { get; init; }

    /// <summary>The user id (or, later, team id) the grant binds.</summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>The custom role granted. FK role_id -> roles(id).</summary>
    public required Guid RoleId { get; init; }

    /// <summary>One of tenant | workspace (stored as a string).</summary>
    public required string ScopeType { get; init; }

    /// <summary>Null for tenant scope, else the workspace id the grant is scoped to.</summary>
    public Guid? ScopeId { get; init; }

    /// <summary>The user who created the grant. A bare id by value, no cross-schema FK.</summary>
    public required Guid GrantedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>tenancy.role_assignments.principal_type values.</summary>
internal static class PrincipalType
{
    public const string User = "user";

    public const string Team = "team";
}

/// <summary>tenancy.role_assignments.scope_type values.</summary>
internal static class AssignmentScope
{
    public const string Tenant = "tenant";

    public const string Workspace = "workspace";
}
