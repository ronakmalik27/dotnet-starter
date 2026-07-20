using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Starter.Platform.Data;

namespace Starter.Platform.Events;

/// <summary>
/// Stages a domain event plus its outbox rows inside the caller's open
/// transaction (doc 07 section 3 write rule: state + domain_events + outbox
/// commit or roll back together, INV-8). One outbox row per lane that has a
/// consumer for the event type (LLD 7.1); the event row is always written -
/// the spine keeps everything even when nobody consumes it yet.
/// </summary>
public sealed class OutboxWriter
{
    private readonly Dictionary<string, Lane[]> _routes;

    public OutboxWriter(IEnumerable<IDomainEventConsumer> consumers)
    {
        _routes = consumers
            .SelectMany(c => c.EventTypes.Select(t => (Type: t, c.Lane)))
            .GroupBy(x => x.Type, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.Lane).Distinct().Order().ToArray(),
                StringComparer.Ordinal);
    }

    /// <summary>Lanes that will receive an outbox row for this event type.</summary>
    internal IReadOnlyList<Lane> Route(string eventType) =>
        _routes.TryGetValue(eventType, out var lanes) ? lanes : [];

    /// <summary>
    /// Adds the event and its outbox rows to the same connection and
    /// transaction as <paramref name="transactionOwner"/>. Throws when no
    /// transaction is open: an event outside its business transaction is
    /// exactly the lost-update/ghost-event bug the outbox exists to prevent.
    /// </summary>
    public async Task EnqueueAsync(
        DbContext transactionOwner,
        DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transactionOwner);
        ArgumentNullException.ThrowIfNull(domainEvent);

        var transaction = transactionOwner.Database.CurrentTransaction
            ?? throw new InvalidOperationException(
                "EnqueueAsync must run inside the business transaction (doc 07 section 3 write rule).");

        var optionsBuilder = new DbContextOptionsBuilder<PlatformDbContext>();
        optionsBuilder
            .UseNpgsql(transactionOwner.Database.GetDbConnection())
            .UseSnakeCaseNamingConvention();

        await using var platform = new PlatformDbContext(optionsBuilder.Options);
        await platform.Database.UseTransactionAsync(
            transaction.GetDbTransaction(), cancellationToken);

        platform.Add(domainEvent);
        foreach (var lane in Route(domainEvent.EventType))
        {
            platform.Add(new OutboxRow { EventId = domainEvent.Id, Lane = lane });
        }

        await platform.SaveChangesAsync(cancellationToken);
    }
}
