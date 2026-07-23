using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.roles row: a tenant-authored CUSTOM role (multi-tenancy.md sections
/// 13, 15, 17). System roles (owner | admin | member) are code, never rows, so
/// this table holds custom roles only and carries no null-tenant exception to
/// the tenant RLS boundary. Tenant-owned in the ordinary way (a real tenant_id
/// column, the RLS discriminator and the query-filter key).
/// <para>
/// A role records WHERE it may be assigned (<see cref="AssignableAt"/>: tenant |
/// workspace | both) and, when it is workspace-local, which workspace owns it
/// (<see cref="WorkspaceId"/>): null for a tenant-owned role visible across the
/// tenant, a set value for a workspace-local role defined and assignable only in
/// that workspace (section 15). Unique on (tenant_id, workspace_id, key), so a
/// key is unique within its owning scope.
/// </para>
/// </summary>
internal sealed class CustomRole : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>The stable, tenant-unique key (per owning scope).</summary>
    public required string Key { get; init; }

    /// <summary>The human-facing name. Editable.</summary>
    public required string Name { get; set; }

    /// <summary>An optional description. Editable.</summary>
    public string? Description { get; set; }

    /// <summary>One of tenant | workspace | both (stored as a string).</summary>
    public required string AssignableAt { get; init; }

    /// <summary>
    /// Null for a tenant-owned role, set for a workspace-local one (the workspace
    /// that owns it and the only scope it may be assigned at, section 15).
    /// </summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>
    /// The platform role-template this role was SEEDED from
    /// (role-templates-and-policy-defaults.md section 2), or null for a
    /// tenant-authored role. A partial unique index (tenant_id, template_key)
    /// WHERE template_key IS NOT NULL makes a re-seed idempotent. Once seeded the
    /// copy is the tenant's own - it may be renamed, re-permissioned, or deleted,
    /// and editing the template later does not retro-change it.
    /// </summary>
    public string? TemplateKey { get; init; }

    /// <summary>The user who authored the role. A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>tenancy.roles.assignable_at values: the scopes a custom role may be granted at.</summary>
internal static class RoleAssignableAt
{
    public const string Tenant = "tenant";

    public const string Workspace = "workspace";

    public const string Both = "both";

    /// <summary>True for a recognized assignable-at value.</summary>
    public static bool IsValid(string value) =>
        value is Tenant or Workspace or Both;

    /// <summary>True when a role with this assignable-at may be granted at the given scope.</summary>
    public static bool Allows(string assignableAt, string scopeType) => scopeType switch
    {
        AssignmentScope.Tenant => assignableAt is Tenant or Both,
        AssignmentScope.Workspace => assignableAt is Workspace or Both,
        _ => false,
    };

    /// <summary>
    /// Maps a role template's <c>assignable_scopes</c> set (a subset of
    /// {tenant, workspace}, role-templates-and-policy-defaults.md section 2) to the
    /// single assignable_at value a seeded custom role carries: both scopes present
    /// is <see cref="Both"/>, workspace only is <see cref="Workspace"/>, otherwise
    /// <see cref="Tenant"/> (the template validation guarantees a non-empty subset,
    /// so the fall-through is the tenant-only case).
    /// </summary>
    public static string FromScopes(IReadOnlyCollection<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        var tenant = scopes.Contains(AssignmentScope.Tenant);
        var workspace = scopes.Contains(AssignmentScope.Workspace);
        return (tenant, workspace) switch
        {
            (true, true) => Both,
            (false, true) => Workspace,
            _ => Tenant,
        };
    }
}
