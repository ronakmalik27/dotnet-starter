using Starter.Platform.Tenancy;

namespace Starter.Platform.Webhooks;

/// <summary>
/// A row of <c>platform.webhook_deliveries</c> (webhooks.md section 2): one
/// <c>(event, endpoint)</c> delivery, written by the fan-out consumer and drained by
/// the delivery worker. Tenant-owned and RLS-enforced. Each row carries its own
/// <see cref="Attempts"/> / <see cref="NextAttemptAt"/> / <see cref="DeadLetteredAt"/>
/// so an endpoint retries and dead-letters independently and a healthy endpoint is
/// never re-hit because a sibling failed (webhooks.md section 1).
/// <para>
/// The unique <c>(endpoint_id, event_id)</c> is the fan-out idempotency key; the
/// stored <see cref="Payload"/> is the delivered body verbatim, so a replay needs no
/// event re-read.
/// </para>
/// </summary>
internal sealed class WebhookDeliveryRow : ITenantOwned
{
    /// <summary>Primary key; also the delivery id carried in the webhook envelope for receiver dedup.</summary>
    public required Guid Id { get; init; }

    /// <summary>The RLS discriminator, stamped from the tenant context on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The target endpoint.</summary>
    public required Guid EndpointId { get; init; }

    /// <summary>The source domain event id (part of the fan-out idempotency key).</summary>
    public required Guid EventId { get; init; }

    /// <summary>The event type, for display and filtering.</summary>
    public required string EventType { get; init; }

    /// <summary>The webhook body (the envelope, webhooks.md section 5), stored so replay needs no event re-read.</summary>
    public required string Payload { get; init; }

    /// <summary>Delivery status: <c>pending</c>, <c>delivered</c>, or <c>dead</c>.</summary>
    public required string Status { get; set; }

    /// <summary>Delivery attempts made so far.</summary>
    public int Attempts { get; set; }

    /// <summary>When the worker may next claim this row.</summary>
    public required DateTimeOffset NextAttemptAt { get; set; }

    /// <summary>Set on a 2xx delivery.</summary>
    public DateTimeOffset? DeliveredAt { get; set; }

    /// <summary>Set after <c>MaxAttempts</c> (or on an unrecoverable failure); the row is then parked for replay.</summary>
    public DateTimeOffset? DeadLetteredAt { get; set; }

    /// <summary>The last HTTP status, or null on a transport error.</summary>
    public int? LastResponseStatus { get; set; }

    /// <summary>A short, bounded, non-PII failure note (never the URL or the secret).</summary>
    public string? LastError { get; set; }

    /// <summary>When the delivery row was created (fan-out time).</summary>
    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>The three delivery states (webhooks.md section 2).</summary>
internal static class WebhookDeliveryStatus
{
    public const string Pending = "pending";

    public const string Delivered = "delivered";

    public const string Dead = "dead";
}
