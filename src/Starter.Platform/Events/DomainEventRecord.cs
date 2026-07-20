namespace Starter.Platform.Events;

/// <summary>
/// A row of platform.domain_events (doc 07 section 3): the INV-8 append-only
/// spine, written in the same transaction as the state it describes. The
/// doc 09 envelope's schemaVersion is a property of the event-type contract
/// and is applied at serialization time, not stored as a column.
/// </summary>
public sealed class DomainEventRecord
{
    public required Guid Id { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>Owning module code: "money", "trips", .. (doc 07 section 2).</summary>
    public required string Module { get; init; }

    /// <summary>Doc 09 catalogue name: "money.expense.created".</summary>
    public required string EventType { get; init; }

    public required Guid EntityId { get; init; }

    /// <summary>Null for non-trip events (identity).</summary>
    public Guid? TripId { get; init; }

    /// <summary>Null when the system acted (scheduled transition).</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>JSON payload; ids, amounts, titles - never PII (doc 09 section 1).</summary>
    public required string Payload { get; init; }
}
