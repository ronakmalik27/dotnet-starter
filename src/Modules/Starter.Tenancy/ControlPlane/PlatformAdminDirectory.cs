using Npgsql;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The platform-admin lookup for the RequirePlatformAdmin gate, run on the
/// bypass data source (multi-tenancy.md section 7). platform.platform_admins is
/// a platform table with no row-level security, so it is read only across the
/// bypass path, never on the request role - which is why this is one of the
/// bypass-containment allowlisted control-plane types.
/// <para>
/// It answers a single yes/no by value (is this user a platform admin), keyed on
/// the primary key. Platform power is never a tenant role: the gate asks this,
/// not the membership table.
/// </para>
/// </summary>
internal sealed class PlatformAdminDirectory(BypassDataSource bypass)
{
    public async Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select 1 from platform.platform_admins where user_id = @user limit 1",
            connection);
        command.Parameters.AddWithValue("user", userId);

        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }
}
