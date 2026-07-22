using Microsoft.Extensions.Options;
using Npgsql;
using Starter.Tenancy.ServiceAccounts;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Resolving a presented API key (service-accounts.md sections 3, 4, 6):
/// CROSS-TENANT control-plane work on the bypass path, because a request
/// authenticated by an API key holds no tid until the key resolves one, so an
/// RLS-bound lookup keyed on the current-tenant GUC would see nothing. The lookup
/// is tenant-less (key_hash is globally unique). This is an allowlisted Tenancy
/// control-plane type, reached through <c>ITenancyApi</c> by the Api-layer
/// authentication handler (the Api layer cannot touch the bypass source itself).
/// <para>
/// Every miss - unknown, revoked, or expired - collapses to one null outcome, so
/// a holder cannot probe which keys exist; the SELECT's liveness predicate does
/// that in one read. For a live key it also does the THROTTLED, coalesced
/// last_used_at write in one statement (section 6): a key hammered by a busy
/// client advances last_used_at at most once per the configured window, keeping
/// the auth path lookup-light. It returns ONLY the (tenant, service-account)
/// pair - the same shape and discipline as invitation accept.
/// </para>
/// </summary>
internal sealed class ApiKeyResolver(
    BypassDataSource bypass,
    Clock clock,
    IOptions<ApiKeyOptions> options)
{
    private readonly ApiKeyOptions _options = options.Value;

    public async Task<(Guid TenantId, Guid ServiceAccountId)?> ResolveApiKeyAsync(
        string keyHash, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(keyHash))
        {
            return null;
        }

        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // The liveness predicate collapses unknown, revoked, and expired to one
        // "no row" outcome. The lookup is tenant-less (key_hash is globally unique
        // under its unique index), so no tenant is bound yet.
        Guid tenantId;
        Guid serviceAccountId;
        await using (var lookup = new NpgsqlCommand(
            "select id, tenant_id from tenancy.service_accounts "
            + "where key_hash = @hash and revoked_at is null "
            + "and (expires_at is null or expires_at > @now) limit 1",
            connection))
        {
            lookup.Parameters.AddWithValue("hash", keyHash);
            lookup.Parameters.AddWithValue("now", now);

            await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            serviceAccountId = reader.GetGuid(0);
            tenantId = reader.GetGuid(1);
        }

        // Throttled, coalesced last_used_at write (section 6): one statement, so a
        // key writes at most once per throttle window. last_used_at is approximate
        // by design (accurate to the throttle); the exact per-call record is the
        // audit log, not this column.
        await using (var touch = new NpgsqlCommand(
            "update tenancy.service_accounts set last_used_at = @now "
            + "where id = @id and (last_used_at is null or last_used_at < @cutoff)",
            connection))
        {
            touch.Parameters.AddWithValue("now", now);
            touch.Parameters.AddWithValue("id", serviceAccountId);
            touch.Parameters.AddWithValue("cutoff", now - _options.LastUsedThrottle);
            await touch.ExecuteNonQueryAsync(cancellationToken);
        }

        return (tenantId, serviceAccountId);
    }
}
