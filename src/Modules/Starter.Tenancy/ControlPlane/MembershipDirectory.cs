using Npgsql;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The membership lookup for the tenant-token mint gate, run on the bypass data
/// source. It is explicitly cross-tenant: the caller holds no tid for the target
/// tenant yet (that is what they are asking to mint), so an RLS-bound query
/// keyed on the current-tenant GUC would see nothing. Reading membership across
/// the boundary is exactly what the bypass role is for. This is one of the two
/// Tenancy types the bypass-containment arch test allowlists.
/// <para>
/// It answers a single yes/no by value (is this user an active member of this
/// tenant), never returns rows, and keys on the unique (tenant_id, user_id)
/// index. A non-member - or an absent tenant - is false, so the endpoint answers
/// 404 and never confirms the tenant exists to a non-member.
/// </para>
/// </summary>
internal sealed class MembershipDirectory(BypassDataSource bypass)
{
    public async Task<bool> IsActiveMemberAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select 1 from tenancy.memberships "
            + "where tenant_id = @tenant and user_id = @user and status = 'active' limit 1",
            connection);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("user", userId);

        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }
}
