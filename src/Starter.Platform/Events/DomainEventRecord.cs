namespace Starter.Platform.Events;

/// <summary>
/// A row of platform.domain_events: the append-only event spine, written in
/// the same transaction as the state it describes. An event type's schema
/// version is a property of its contract and is applied at serialization time,
/// not stored as a column.
/// </summary>
public sealed class DomainEventRecord
{
    public required Guid Id { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>Owning module code, e.g. "identity", "sample".</summary>
    public required string Module { get; init; }

    /// <summary>Catalogue name, e.g. "sample.note.created".</summary>
    public required string EventType { get; init; }

    /// <summary>The entity the event is about.</summary>
    public required Guid EntityId { get; init; }

    /// <summary>Null when the system acted (a scheduled job, not a user).</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>
    /// The tenant this event belongs to, or null for a genuinely platform-level
    /// event. Stamped by <see cref="OutboxWriter"/> from the ambient tenant at
    /// enqueue - not set by the emitting module - so the value can never
    /// disagree with the tenant the enqueue ran under. On dispatch it drives
    /// the consumer's tenant so the consumer runs under the same RLS boundary.
    /// </summary>
    public Guid? TenantId { get; internal set; }

    /// <summary>JSON payload; ids and scalars, never PII.</summary>
    public required string Payload { get; init; }
}
