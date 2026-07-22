using Npgsql;

namespace Starter.Platform.Auth;

/// <summary>
/// The out-of-band first-platform-admin seed (multi-tenancy.md sections 6 and
/// 7): the first platform super-admin is established at startup from
/// configuration, NEVER self-granted through the API. When
/// <c>Platform:BootstrapAdminUserId</c> is set to a user's guid, the composition
/// root calls this after migrations and grants to ensure that user is a platform
/// admin. It is idempotent (insert on conflict do nothing), so it is safe on
/// every boot, and it runs on the bypass connection because platform tables live
/// off the request role's reach.
/// </summary>
public static class PlatformAdminSeed
{
    /// <summary>
    /// Ensures <paramref name="userId"/> is a platform admin, granted out of band
    /// (granted_by null). Idempotent: a row that already exists is left as it is.
    /// Runs on the supplied bypass connection string.
    /// </summary>
    public static async Task EnsureAsync(
        string bypassConnectionString,
        Guid userId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bypassConnectionString);

        await using var connection = new NpgsqlConnection(bypassConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into platform.platform_admins (user_id, granted_by, granted_at) "
            + "values (@userId, null, now()) on conflict (user_id) do nothing",
            connection);
        command.Parameters.AddWithValue("userId", userId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
