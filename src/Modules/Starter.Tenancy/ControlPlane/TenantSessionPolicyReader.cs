using Npgsql;
using Starter.Platform.Auth;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The <see cref="ITenantSessionPolicyReader"/> implementation for the tid-token
/// mint (role-templates-and-policy-defaults.md section 5), run on the bypass data
/// source. Like <see cref="MembershipDirectory"/> it is explicitly cross-tenant:
/// the caller holds no tid for the target tenant at select-tenant time, and the
/// refresh path carries a tid but resolves no request-scoped active tenant, so an
/// RLS-bound read keyed on the current-tenant GUC would see nothing. Reading one
/// tenant's own <c>session_max_seconds</c> across the boundary is exactly what the
/// bypass role is for. This is one of the Tenancy types the bypass-containment arch
/// test allowlists.
/// <para>
/// It answers a single nullable integer by value (the tenant's override, or null
/// when it inherits the platform default), keyed on the tenant's primary key. A
/// missing tenant is null (inherit).
/// </para>
/// </summary>
internal sealed class TenantSessionPolicyReader(BypassDataSource bypass) : ITenantSessionPolicyReader
{
    public async Task<int?> GetSessionMaxSecondsAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select session_max_seconds from tenancy.tenants where id = @id limit 1", connection);
        command.Parameters.AddWithValue("id", tenantId);

        // ExecuteScalar returns null for no row and DBNull for a NULL column; both
        // mean "no override, inherit the platform default".
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? null : (int)result;
    }
}
