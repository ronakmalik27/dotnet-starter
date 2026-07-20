namespace Starter.Platform.Events;

/// <summary>
/// A row of platform.processed_events: one claim per (consumer, event)
/// pair, the dedup ledger behind <see cref="ProcessedEventStore"/>. The
/// composite primary key is the dedup key; processed_at is a default-now
/// audit stamp. Insert-only, never updated - a claimed row stays claimed.
/// </summary>
internal sealed class ProcessedEventRow
{
    /// <summary>The consumer that claimed the event (its stable name).</summary>
    public required string Consumer { get; init; }

    /// <summary>The domain event id, unique per consumer via the composite key.</summary>
    public required Guid EventId { get; init; }

    /// <summary>Set database-side to now() on insert; audit only.</summary>
    public DateTimeOffset ProcessedAt { get; init; }
}
