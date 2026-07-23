using Npgsql;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Resolving a presented SCIM bearer (sso-and-scim.md section 5): CROSS-TENANT
/// control-plane work on the bypass path, because a request authenticated by a SCIM
/// token holds no tid until the token resolves one, so an RLS-bound lookup keyed on
/// the current-tenant GUC would see nothing. The lookup is tenant-less (token_hash
/// is globally unique). This is the ONE new bypass slice this increment adds -
/// allowlisted by the bypass-containment arch test, exactly like
/// <see cref="ApiKeyResolver"/>. It reaches through <c>ITenancyApi</c> from the
/// Api-layer SCIM authentication handler (the Api layer cannot touch the bypass
/// source itself).
/// <para>
/// Every miss - unknown, revoked, or expired - collapses to one null outcome, so a
/// holder cannot probe which tokens exist; the SELECT's liveness predicate does that
/// in one read. It returns ONLY the resolved tenant id - the token carries no other
/// authority (the tid-scoped bearer IS the authority for the SCIM surface).
/// </para>
/// </summary>
internal sealed class ScimTokenResolver(BypassDataSource bypass, Clock clock)
{
    public async Task<Guid?> ResolveScimTokenAsync(string tokenHash, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(tokenHash))
        {
            return null;
        }

        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // The liveness predicate collapses unknown, revoked, and expired to one "no
        // row" outcome. The lookup is tenant-less (token_hash is globally unique under
        // its unique index), so no tenant is bound yet.
        await using var command = new NpgsqlCommand(
            "select tenant_id from tenancy.scim_tokens "
            + "where token_hash = @hash and revoked_at is null "
            + "and (expires_at is null or expires_at > @now) limit 1",
            connection);
        command.Parameters.AddWithValue("hash", tokenHash);
        command.Parameters.AddWithValue("now", now);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? null : (Guid)result;
    }
}
