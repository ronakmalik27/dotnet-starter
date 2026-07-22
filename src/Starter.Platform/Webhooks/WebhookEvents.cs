using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The webhook endpoint lifecycle events (webhooks.md section 8). These are
/// tenant-scoped <c>tenancy.webhook.*</c> events, but the feature lives in Platform
/// (which cannot reference the Tenancy module), so the factories are defined here next
/// to the Platform-registered admin service that emits them. <c>OutboxWriter</c> stamps
/// <c>tenant_id</c> from the tenant the enqueue runs under (the RLS-bound request
/// context), so each row lands scoped to the acting tenant without the service setting
/// it.
/// <para>
/// Payloads carry ids and coarse metadata only - NEVER the receiver URL or the signing
/// secret (a receiver URL can itself embed a token, and these events are both audited
/// and, via the deliverable catalogue, delivered to webhooks, so the payload is an
/// external boundary, webhooks.md sections 3, 5).
/// </para>
/// </summary>
internal static class WebhookEvents
{
    private const string Module = "tenancy";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>tenancy.webhook.endpoint_created: a tenant registered a webhook endpoint.</summary>
    public const string EndpointCreatedType = "tenancy.webhook.endpoint_created";

    /// <summary>tenancy.webhook.endpoint_updated: a tenant changed a webhook endpoint's url, description, subscriptions, or disabled state.</summary>
    public const string EndpointUpdatedType = "tenancy.webhook.endpoint_updated";

    /// <summary>tenancy.webhook.endpoint_deleted: a tenant removed a webhook endpoint.</summary>
    public const string EndpointDeletedType = "tenancy.webhook.endpoint_deleted";

    /// <summary>tenancy.webhook.secret_rotated: a tenant rotated a webhook endpoint's signing secret.</summary>
    public const string SecretRotatedType = "tenancy.webhook.secret_rotated";

    // Each factory constructs its record inline (rather than through a shared helper):
    // the catalogue-completeness test reflects over EVERY static method returning
    // DomainEventRecord on a *Events type, so a shared helper would be invoked as a
    // "factory" with a null event type. Keeping only the four literal-typed factories
    // keeps the reflection scan honest.

    public static DomainEventRecord EndpointCreated(Guid endpointId, Guid actorUserId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = EndpointCreatedType,
        EntityId = endpointId,
        ActorUserId = actorUserId,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    public static DomainEventRecord EndpointUpdated(Guid endpointId, Guid actorUserId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = EndpointUpdatedType,
        EntityId = endpointId,
        ActorUserId = actorUserId,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    public static DomainEventRecord EndpointDeleted(Guid endpointId, Guid actorUserId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = EndpointDeletedType,
        EntityId = endpointId,
        ActorUserId = actorUserId,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    public static DomainEventRecord SecretRotated(Guid endpointId, Guid actorUserId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = SecretRotatedType,
        EntityId = endpointId,
        ActorUserId = actorUserId,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };
}
