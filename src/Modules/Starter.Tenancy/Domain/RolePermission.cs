using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.role_permissions row: one permission a custom role grants
/// (multi-tenancy.md section 17). Tenant-owned and under the tenant RLS like
/// every other tenant table, so a raw read cannot cross tenants; the tenant_id
/// is denormalized from the owning role so the row carries the RLS discriminator
/// directly. Holds custom-role rows only - system-role permission sets live in
/// code. Primary key (role_id, permission); an intra-schema FK role_id ->
/// roles(id) cascades a role's permissions away when the role is deleted.
/// </summary>
internal sealed class RolePermission : ITenantOwned
{
    public required Guid RoleId { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>A permission key from the closed catalogue (Permissions).</summary>
    public required string Permission { get; init; }
}
