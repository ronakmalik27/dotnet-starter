using Npgsql;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The per-request impersonation guard's grant re-check, run on the bypass data
/// source (multi-tenancy.md section 7). It implements the platform-declared
/// <see cref="IImpersonationGrantReader"/> port, so the guard middleware in the
/// platform never references this module. platform.impersonation_grants is a
/// platform table with no row-level security, read only across the bypass path -
/// which is why this is one of the bypass-containment allowlisted control-plane
/// types.
/// <para>
/// The expiry check uses the database clock (now()), so it is monotonic with the
/// grant's own issued_at / expires_at stamps and needs no ambient clock. A
/// missing, ended, or expired grant is simply false.
/// </para>
/// </summary>
internal sealed class ImpersonationGrantReader(BypassDataSource bypass) : IImpersonationGrantReader
{
    public async Task<bool> IsGrantActiveAsync(Guid grantId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select 1 from platform.impersonation_grants "
            + "where id = @id and ended_at is null and expires_at > now() limit 1",
            connection);
        command.Parameters.AddWithValue("id", grantId);

        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }
}
