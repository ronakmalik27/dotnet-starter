namespace Starter.Platform.Events;

/// <summary>
/// A row of platform.outbox, keyed (event_id, lane) so
/// each lane drains on its own cursor. Delivered rows are purged
/// after 7 days; poisoned rows are parked (delivered_at stays null) and
/// wait for the replay tool.
/// </summary>
public sealed class OutboxRow
{
    public required Guid EventId { get; init; }

    public required Lane Lane { get; init; }

    /// <summary>
    /// The event's tenant (null for a platform event), copied from the
    /// domain-event row at enqueue so the dispatcher can bind the consumer's
    /// tenant from the claimed outbox row.
    /// </summary>
    public Guid? TenantId { get; init; }

    public DateTimeOffset EnqueuedAt { get; init; }

    public int Attempts { get; set; }

    public DateTimeOffset NextAttemptAt { get; set; }

    public DateTimeOffset? DeliveredAt { get; set; }

    public DateTimeOffset? PoisonedAt { get; set; }
}
