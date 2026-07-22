using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Events;

/// <summary>
/// Stages a domain event plus its outbox rows inside the caller's open
/// transaction (state + domain_events + outbox
/// commit or roll back together in the same transaction). One outbox row per lane that has a
/// consumer for the event type; the event row is always written -
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
                "EnqueueAsync must run inside the business transaction.");

        // Stamp the event's tenant from the tenant the enqueue is running
        // under (the owning context's tenant), never from the emitting module.
        // Null when there is no tenant (a platform event). The platform tables
        // carry no RLS, so this context needs no tenant of its own.
        var tenantId = TenantOf(transactionOwner);
        domainEvent.TenantId = tenantId;

        var optionsBuilder = new DbContextOptionsBuilder<PlatformDbContext>();
        optionsBuilder
            .UseNpgsql(transactionOwner.Database.GetDbConnection())
            .UseSnakeCaseNamingConvention();

        await using var platform = new PlatformDbContext(optionsBuilder.Options, NoTenant.Instance);
        await platform.Database.UseTransactionAsync(
            transaction.GetDbTransaction(), cancellationToken);

        platform.Add(domainEvent);
        foreach (var lane in Route(domainEvent.EventType))
        {
            platform.Add(new OutboxRow { EventId = domainEvent.Id, Lane = lane, TenantId = tenantId });
        }

        await platform.SaveChangesAsync(cancellationToken);
    }

    private static Guid? TenantOf(DbContext transactionOwner)
    {
        if (transactionOwner is ModuleDbContext moduleContext
            && moduleContext.TenantContext.IsResolved)
        {
            return moduleContext.TenantContext.TenantId;
        }

        return null;
    }
}
