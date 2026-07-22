using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The webhook fan-out consumer (webhooks.md section 3): a Platform Fast-lane
/// <see cref="IDomainEventConsumer"/> that, for each tenant-scoped domain event, inserts
/// one <c>webhook_deliveries</c> row per subscribed, non-disabled endpoint. The HTTP call
/// is the worker's job; this only writes rows.
/// <para>
/// Like the audit projection it resolves the request-style (RLS-bound)
/// <see cref="PlatformDbContext"/> from the passed scope (never the bypass source): the
/// dispatcher binds the tenant from the event's tenant_id before this runs, so both the
/// endpoint read and the delivery insert are scoped to exactly that tenant by row-level
/// security. Payloads are read as untyped JSON (Platform references no module type).
/// </para>
/// <para>
/// It shares its Fast-lane outbox row with the audit projection, so it must be idempotent
/// and must never throw on a benign redelivery: the insert is <c>ON CONFLICT DO NOTHING</c>
/// on the unique <c>(endpoint_id, event_id)</c>, so a redelivered event is a no-op and the
/// shared row is never poisoned.
/// </para>
/// </summary>
internal sealed class WebhookFanoutConsumer : IDomainEventConsumer
{
    public Lane Lane => Lane.Fast;

    /// <summary>The shared tenant-scoped deliverable catalogue (webhooks.md section 3), the same set the audit projection lists.</summary>
    public IReadOnlyCollection<string> EventTypes => DeliverableEvents.TenantScoped;

    public async Task ConsumeAsync(
        IServiceProvider services,
        DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(domainEvent);

        var db = services.GetRequiredService<PlatformDbContext>();
        var tenant = services.GetRequiredService<ITenantContext>();
        var clock = services.GetRequiredService<Clock>();

        // The transaction is what makes the interceptor set the tenant GUC, so both the
        // read and the inserts run under RLS for the event's tenant.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        var endpointIds = await MatchingEndpointsAsync(connection, dbTransaction, domainEvent.EventType, cancellationToken);
        foreach (var endpointId in endpointIds)
        {
            var deliveryId = Ids.NewId(clock.UtcNow);
            var payload = WebhookEnvelope.Build(
                deliveryId, domainEvent.EventType, domainEvent.OccurredAt, domainEvent.Payload);

            await using var insert = new NpgsqlCommand(
                """
                insert into platform.webhook_deliveries
                  (id, tenant_id, endpoint_id, event_id, event_type, payload, status, attempts, next_attempt_at, created_at)
                values ($1, $2, $3, $4, $5, $6::jsonb, 'pending', 0, now(), now())
                on conflict (endpoint_id, event_id) do nothing
                """,
                connection,
                dbTransaction)
            {
                Parameters =
                {
                    new() { Value = deliveryId },
                    // Stamped from the tenant context, never from the payload. RLS's
                    // WITH CHECK rejects the write if it disagrees with the GUC.
                    new() { Value = tenant.TenantId },
                    new() { Value = endpointId },
                    new() { Value = domainEvent.Id },
                    new() { Value = domainEvent.EventType },
                    // The stored body is the webhook ENVELOPE (webhooks.md section 5),
                    // not the raw event payload: the worker POSTs this verbatim, so the
                    // receiver gets { id, type, occurredAt, data } and the envelope id
                    // matches this delivery row's id (its dedup key).
                    new() { Value = payload },
                },
            };
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<List<Guid>> MatchingEndpointsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string eventType,
        CancellationToken cancellationToken)
    {
        // Non-disabled endpoints subscribed to this event type: an empty event_types
        // array means "all deliverable events". RLS scopes this to the event's tenant.
        await using var read = new NpgsqlCommand(
            """
            select id from platform.webhook_endpoints
            where disabled_at is null
              and (cardinality(event_types) = 0 or $1 = any(event_types))
            """,
            connection,
            transaction)
        {
            Parameters = { new() { Value = eventType } },
        };

        var ids = new List<Guid>();
        await using var reader = await read.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }
}
