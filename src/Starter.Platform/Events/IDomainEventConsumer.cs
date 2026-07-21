namespace Starter.Platform.Events;

/// <summary>
/// A subscriber the dispatcher calls in-process (domain events are the
/// only cross-module write trigger). Delivery is
/// at-least-once: every consumer MUST dedupe by event id. There are two
/// dedup shapes, and a consumer picks the one that matches its effect:
/// <list type="bullet">
///   <item>Best-effort, non-transactional effect (e.g. sending an email):
///   claim the event through <see cref="ProcessedEventStore"/> BEFORE the
///   effect. The claim commits on its own connection, so a redelivery sees
///   it taken and skips - at the price that an effect which fails after the
///   claim is dropped, not retried (the notifications consumer's tradeoff).</item>
///   <item>Transactional effect that must be exactly-once with its dedup:
///   do NOT use <see cref="ProcessedEventStore"/> (its claim runs on its own
///   connection and cannot join the effect's transaction). Instead insert a
///   dedup row through the consumer's OWN DbContext, enlisted in the same
///   transaction as the effect, so claim and effect commit or roll back
///   together.</item>
/// </list>
/// A consumer's lane decides which outbox row feeds it.
/// Implementations are held by the singleton dispatcher for the process
/// lifetime: they must be singleton-safe and resolve any scoped
/// dependencies (DbContexts) per consume call, never via constructor
/// injection.
/// </summary>
public interface IDomainEventConsumer
{
    /// <summary>Fast for in-process work, Slow for provider calls.</summary>
    Lane Lane { get; }

    /// <summary>Catalogue names this consumer subscribes to.</summary>
    IReadOnlyCollection<string> EventTypes { get; }

    Task ConsumeAsync(DomainEventRecord domainEvent, CancellationToken cancellationToken);
}
