namespace Starter.Platform.Events;

/// <summary>
/// A subscriber the dispatcher calls in-process (LLD 7.1; HLD 3.2 rule 4:
/// domain events are the only cross-module write trigger). Delivery is
/// at-least-once: every consumer MUST dedupe by event id (doc 09
/// section 1). A consumer's lane decides which outbox row feeds it.
/// Implementations are held by the singleton dispatcher for the process
/// lifetime: they must be singleton-safe and resolve any scoped
/// dependencies (DbContexts) per consume call, never via constructor
/// injection.
/// </summary>
public interface IDomainEventConsumer
{
    /// <summary>Fast for in-process work, Slow for provider calls (LLD 7.1).</summary>
    Lane Lane { get; }

    /// <summary>Doc 09 catalogue names this consumer subscribes to.</summary>
    IReadOnlyCollection<string> EventTypes { get; }

    Task ConsumeAsync(DomainEventRecord domainEvent, CancellationToken cancellationToken);
}
