using Starter.Platform.Dsar;

namespace Starter.Tenancy.Dsar;

/// <summary>
/// The Tenancy module's erasure declaration (data-export-and-erasure.md section 4):
/// the full tenant-owned tenancy set, in FK-safe delete order (children before
/// parents). <c>role_assignments</c> and <c>role_permissions</c> precede <c>roles</c>
/// (their FK target); <c>team_members</c> precedes <c>teams</c>. The custom-role table
/// is named <c>roles</c> (NOT <c>custom_roles</c>). <c>tenancy.tenants</c> is declared
/// LAST and keys on its own <c>id</c> (there is no <c>tenant_id</c> column) - and since
/// Tenancy is the last-registered module, this is the last table purged overall.
/// Declaration only - this touches no bypass, so the module stays clean under the
/// bypass-containment arch test.
/// </summary>
internal sealed class TenancyErasureContributor : ITenantErasureContributor
{
    public IReadOnlyList<TenantTable> Tables { get; } =
    [
        new("tenancy.role_assignments", "tenant_id"),
        new("tenancy.role_permissions", "tenant_id"),
        new("tenancy.team_members", "tenant_id"),
        new("tenancy.teams", "tenant_id"),
        new("tenancy.roles", "tenant_id"),
        new("tenancy.invitations", "tenant_id"),
        new("tenancy.service_accounts", "tenant_id"),
        // Enterprise SSO (sso-and-scim.md sections 2, 7): both tenant-owned, no FK
        // into the rest of the set, so they purge anywhere before tenancy.tenants.
        // sso_configs' client_secret_encrypted is [Sensitive] - redacted in the
        // operator snapshot by the reflection-driven completeness mechanism.
        new("tenancy.sso_configs", "tenant_id"),
        new("tenancy.sso_domain_claims", "tenant_id"),
        new("tenancy.memberships", "tenant_id"),
        new("tenancy.workspaces", "tenant_id"),
        // The tenant boundary itself, keyed on its own id, deleted LAST.
        new("tenancy.tenants", "id"),
    ];
}
