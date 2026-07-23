namespace Starter.Platform.Data;

/// <summary>
/// A platform.role_templates row: one operator-owned role template
/// (role-templates-and-policy-defaults.md section 2). A template is a global,
/// no-RLS catalogue entry (like <see cref="PlanRow"/> and the platform-admin
/// roster) that the super-admin SEEDS into every tenant as one of that tenant's
/// own custom roles. Seeding creates a COPY (a tenancy.roles row stamped with the
/// template key); editing the template later does NOT retro-change already-seeded
/// copies. A tenant never edits a template - it consumes it.
/// <para>
/// <see cref="Permissions"/> is a NOT-NULL text[] of permission atoms from the
/// closed catalogue (validated against <c>Permissions.All</c> on write, with none
/// owner-reserved), and <see cref="AssignableScopes"/> is a NOT-NULL text[] subset
/// of {tenant, workspace} (the custom-role scope vocabulary). Both differ from the
/// plan catalogue's NULL-means-unrestricted arrays: a template names an EXACT set,
/// never "unrestricted".
/// </para>
/// <para>
/// EF maps this so the migration generates the table; the super-admin CRUD writes
/// it with raw SQL on the bypass path (the same shape the plan catalogue uses),
/// and the request role is REVOKE'd write on it in the TenantRoleProvisioner grant
/// pass, so a tenant can never edit the operator catalogue.
/// </para>
/// </summary>
internal sealed class RoleTemplateRow
{
    /// <summary>Primary key; the stable template identifier stamped onto a seeded role's template_key.</summary>
    public required string Key { get; init; }

    /// <summary>The role name seeded into the tenant.</summary>
    public required string Name { get; init; }

    /// <summary>A human-facing description.</summary>
    public required string Description { get; init; }

    /// <summary>The permission atoms the seeded role grants (closed catalogue; never owner-reserved).</summary>
    public required string[] Permissions { get; init; }

    /// <summary>The scopes the seeded role may be assigned at: a subset of {tenant, workspace}.</summary>
    public required string[] AssignableScopes { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}
