using Npgsql;

namespace Starter.Platform.Events;

/// <summary>
/// The outbox retention purge (doc 07 sections 3 and 13): delivered rows
/// older than the retention window are deleted in batches; poisoned rows
/// are never touched - they wait for the doc 11 replay tool. Scheduling
/// belongs to the LLD 7.3 generic purger story; the query lives here so
/// the exclusion rule is owned and tested with the outbox.
/// </summary>
public sealed class OutboxMaintenance(NpgsqlDataSource dataSource)
{
    /// <summary>Returns the number of rows purged.</summary>
    public async Task<int> PurgeDeliveredAsync(
        TimeSpan retention,
        CancellationToken cancellationToken,
        int batchSize = 1000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        var total = 0;
        while (true)
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(
                """
                delete from platform.outbox
                where ctid in (
                  select ctid from platform.outbox
                  where delivered_at is not null
                    and delivered_at < now() - make_interval(secs => $1)
                    and poisoned_at is null
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
