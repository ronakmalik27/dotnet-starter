namespace Starter.Platform.Events;

/// <summary>
/// A subscriber the dispatcher calls in-process (domain events are the
/// only cross-module write trigger). Delivery is
/// at-least-once: every consumer MUST dedupe by event id. A consumer's
/// lane decides which outbox row feeds it.
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
