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
/// workspace (scope_id = the workspace). The principal is a user (a member), a
/// team (unions into every member's set), or a service_account (a non-human
/// principal whose effective permissions are exactly its grants,
/// service-accounts.md section 4). Uniqueness is a partial unique index per scope
/// kind (one WHERE scope_type = 'tenant', one for workspace scope including
/// scope_id), because a null scope_id would not collide under a plain unique
/// constraint.
/// </para>
/// </summary>
internal sealed class RoleAssignment : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>One of user | team | service_account (stored as a string).</summary>
    public required string PrincipalType { get; init; }

    /// <summary>The user, team, or service-account id the grant binds.</summary>
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

    /// <summary>
    /// The optional ABAC condition envelope (abac.md sections 2, 3), stored as
    /// jsonb. Null = unconditional (every grant today), so the grant behaves
    /// exactly as it does now. When set, the grant's permissions count only for a
    /// request whose attributes satisfy the condition, evaluated live at the
    /// per-request permission check - never memoized into the cached effective set.
    /// It is tenant policy config, NOT a secret (exported in the tenant DSAR bundle).
    /// </summary>
    public string? Condition { get; init; }
}

/// <summary>tenancy.role_assignments.principal_type values.</summary>
internal static class PrincipalType
{
    public const string User = "user";

    public const string Team = "team";

    public const string ServiceAccount = "service_account";
}

/// <summary>tenancy.role_assignments.scope_type values.</summary>
internal static class AssignmentScope
{
    public const string Tenant = "tenant";

    public const string Workspace = "workspace";
}
