using Npgsql;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The default <see cref="IPolicyDefaults"/>: a raw read of the no-RLS
/// <c>platform.policy_defaults</c> singleton (role-templates-and-policy-defaults.md
/// section 3) through the request-role data source, behind a SHORT in-process TTL
/// cache. It is a SINGLETON, not request-scoped, because the login hot path reads it
/// under concurrent brute-force traffic and per-request caching would not help
/// across attempts; the cache is shared process-wide and the super-admin write path
/// calls <see cref="Invalidate"/> so an edit lands immediately in-process.
/// <para>
/// It reads on the normal request-role <see cref="NpgsqlDataSource"/> (the table has
/// no RLS and the request role keeps SELECT on it), never the bypass source, so this
/// stays request/consumer code by placement. It FAILS CLOSED to the built-in
/// constants (<see cref="PolicyDefaults.BuiltIn"/>) when the row is absent and never
/// throws on the auth path: a transient read failure returns the constants without
/// poisoning the cache, so the next call retries.
/// </para>
/// </summary>
internal sealed class PolicyDefaultsReader(NpgsqlDataSource dataSource, Clock clock) : IPolicyDefaults
{
    // Short by design: long enough to absorb a brute-force burst's reads, short
    // enough that a policy change propagates fleetly even without the explicit
    // invalidation the write path also performs.
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(5);

    private const string SelectSql =
        "select password_min_length, access_token_lifetime_seconds, refresh_lifetime_seconds, "
        + "lockout_max_attempts, lockout_duration_seconds from platform.policy_defaults where one_row limit 1";

    // A single immutable snapshot swapped atomically (reference assignment is
    // atomic); a concurrent miss may read twice, which is harmless for a trivial
    // read. volatile so a writer's swap is promptly visible to other threads.
    private volatile CacheEntry? _cache;

    public async Task<PolicyDefaults> GetAsync(CancellationToken cancellationToken)
    {
        var cached = _cache;
        if (cached is not null && cached.ExpiresAt > clock.UtcNow)
        {
            return cached.Value;
        }

        PolicyDefaults value;
        try
        {
            value = await ReadAsync(cancellationToken) ?? PolicyDefaults.BuiltIn;
        }
        catch (NpgsqlException)
        {
            // Never throw on the auth path: a transient read failure serves the
            // built-in constants WITHOUT caching, so the next call retries the DB.
            return PolicyDefaults.BuiltIn;
        }

        _cache = new CacheEntry(value, clock.UtcNow + CacheTtl);
        return value;
    }

    public void Invalidate() => _cache = null;

    private async Task<PolicyDefaults?> ReadAsync(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(SelectSql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            // The singleton is absent (a DB that has not run the seed): the caller
            // falls back to the built-in constants.
            return null;
        }

        return new PolicyDefaults(
            reader.GetInt32(0),
            reader.GetInt32(1),
            reader.GetInt32(2),
            reader.GetInt32(3),
            reader.GetInt32(4));
    }

    private sealed record CacheEntry(PolicyDefaults Value, DateTimeOffset ExpiresAt);
}
