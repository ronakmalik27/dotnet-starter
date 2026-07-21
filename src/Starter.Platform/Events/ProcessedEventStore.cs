using Npgsql;

namespace Starter.Platform.Events;

/// <summary>
/// The reusable at-least-once dedup store. A consumer claims an event by
/// its (consumer, event id) pair before acting on it; the claim is a single
/// INSERT .. ON CONFLICT DO NOTHING against platform.processed_events, so
/// concurrent or redelivered claims of the same pair cannot both win. The
/// first claim returns true (this delivery owns the work); every later claim
/// returns false (a prior delivery already did). Constructed with the
/// shared <see cref="NpgsqlDataSource"/> singleton, so it is itself
/// singleton-safe and holds no per-request state.
/// <para>
/// Important scope: <see cref="TryRecordAsync"/> opens its OWN connection and
/// commits the claim on its own. The claim is therefore NOT part of any
/// caller's transaction - it stands alone. That is exactly right for the
/// claim-before-best-effort-effect shape (the notifications consumer), where
/// the effect is non-transactional anyway. It is the WRONG tool for a
/// consumer that needs its dedup claim and its effect to commit atomically:
/// such a consumer must record its own dedup row through its OWN DbContext,
/// enlisted in the same transaction as the effect, rather than calling this
/// store. See <see cref="IDomainEventConsumer"/> for the two dedup shapes.
/// </para>
/// </summary>
public sealed class ProcessedEventStore(NpgsqlDataSource dataSource)
{
    /// <summary>
    /// Records that <paramref name="consumer"/> has claimed
    /// <paramref name="eventId"/>. Returns true when this call inserted the
    /// claim (first time), false when the pair was already recorded (a prior
    /// delivery). The ON CONFLICT DO NOTHING makes the claim atomic: two
    /// racing deliveries see exactly one insert.
    /// </summary>
    public async Task<bool> TryRecordAsync(string consumer, Guid eventId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(consumer);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into platform.processed_events (consumer, event_id) values ($1, $2) on conflict do nothing",
            connection)
        {
            Parameters = { new() { Value = consumer }, new() { Value = eventId } },
        };

        // ExecuteNonQuery returns the affected-row count: 1 on a fresh
        // insert, 0 when the conflict clause swallowed a duplicate.
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        return inserted == 1;
    }
}
