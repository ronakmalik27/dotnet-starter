using Npgsql;

namespace Starter.Platform.Http;

/// <summary>
/// The idempotency retention purge (14 days): rows past
/// the window are deleted in batches. Scheduling belongs to the
/// generic purger job (hourly slot); the query lives here so the
/// retention rule is owned and tested with the idempotency store - the
/// same split as OutboxMaintenance.
/// </summary>
public sealed class IdempotencyMaintenance(NpgsqlDataSource dataSource)
{
    /// <summary>The retention window.</summary>
    public static readonly TimeSpan DefaultRetention = TimeSpan.FromDays(14);

    /// <summary>Returns the number of rows purged.</summary>
    public async Task<int> PurgeExpiredAsync(
        TimeSpan retention,
        CancellationToken cancellationToken,
        int batchSize = 1000)
    {
        // A zero or negative window would purge live keys and break the
        // replay guarantee; reject it before any delete runs.
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(retention, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        var total = 0;
        while (true)
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(
                """
                delete from platform.idempotency_keys
                where ctid in (
                  select ctid from platform.idempotency_keys
                  where created_at < now() - make_interval(secs => $1)
                  limit $2)
                """,
                connection)
            {
                Parameters =
                {
                    new() { Value = retention.TotalSeconds },
                    new() { Value = batchSize },
                },
            };

            var purged = await command.ExecuteNonQueryAsync(cancellationToken);
            total += purged;
            if (purged < batchSize)
            {
                return total;
            }
        }
    }
}
