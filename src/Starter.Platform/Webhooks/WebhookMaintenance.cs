using Starter.Platform.Tenancy;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The webhook-delivery retention purge (webhooks.md section 9): delivered rows older
/// than the retention window are deleted in batches on the BYPASS path (the deliveries
/// table is RLS-owned, and the purge crosses tenants); dead rows are NEVER touched - they
/// are the dead-letter, kept for inspection and replay, exactly as the outbox keeps
/// poisoned rows. Scheduling belongs to the generic purger job; the query lives here so
/// the exclusion rule is owned and tested with the feature. Mirrors <c>OutboxMaintenance</c>.
/// </summary>
public sealed class WebhookMaintenance(BypassDataSource bypass)
{
    private readonly BypassDataSource _bypass = bypass ?? throw new ArgumentNullException(nameof(bypass));

    /// <summary>Returns the number of delivered rows purged.</summary>
    public async Task<int> PurgeDeliveredAsync(
        TimeSpan retention,
        CancellationToken cancellationToken,
        int batchSize = 1000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        var total = 0;
        while (true)
        {
            await using var connection = await _bypass.DataSource.OpenConnectionAsync(cancellationToken);
            await using var command = new Npgsql.NpgsqlCommand(
                """
                delete from platform.webhook_deliveries
                where ctid in (
                  select ctid from platform.webhook_deliveries
                  where status = 'delivered'
                    and delivered_at is not null
                    and delivered_at < now() - make_interval(secs => $1)
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
