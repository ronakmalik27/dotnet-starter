using Starter.Platform.Paging;
using Starter.SharedKernel;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The tenant webhook control plane (webhooks.md section 7), a Platform-registered,
/// RLS-bound service the Api endpoints call. It lives in Platform (the feature does,
/// next to the outbox and audit log) so the Api layer never touches the internal
/// <c>PlatformDbContext</c> or the bypass path: every operation here runs on the active
/// tenant under row-level security. The raw signing secret is returned ONCE at register
/// and rotate and never afterward.
/// </summary>
public interface IWebhookAdmin
{
    /// <summary>Registers an endpoint (webhooks.md section 7). Returns the signing secret ONCE.</summary>
    Task<Result<RegisteredWebhook>> RegisterAsync(
        Guid callerUserId,
        string url,
        string? description,
        IReadOnlyList<string>? eventTypes,
        CancellationToken cancellationToken);

    /// <summary>Lists the tenant's endpoints (never the secret; only the prefix, url, subscriptions, disabled state).</summary>
    Task<Result<CursorPage<WebhookEndpointView>>> ListEndpointsAsync(
        int limit, string? cursor, CancellationToken cancellationToken);

    /// <summary>Updates an endpoint's url / description / event types / disabled state.</summary>
    Task<Result<WebhookEndpointView>> UpdateAsync(
        Guid callerUserId,
        Guid endpointId,
        string? url,
        string? description,
        IReadOnlyList<string>? eventTypes,
        bool? disabled,
        CancellationToken cancellationToken);

    /// <summary>Rotates an endpoint's signing secret. Returns the new secret ONCE; the old one stops signing immediately.</summary>
    Task<Result<RotatedWebhookSecret>> RotateSecretAsync(
        Guid callerUserId, Guid endpointId, CancellationToken cancellationToken);

    /// <summary>Removes an endpoint and its pending deliveries together, transactionally.</summary>
    Task<Result> DeleteAsync(Guid callerUserId, Guid endpointId, CancellationToken cancellationToken);

    /// <summary>Lists an endpoint's delivery log (status, attempts, last response, timestamps), keyset-paginated.</summary>
    Task<Result<CursorPage<WebhookDeliveryView>>> ListDeliveriesAsync(
        Guid endpointId, int limit, string? cursor, CancellationToken cancellationToken);

    /// <summary>Resets a delivery to pending (attempts 0) so the worker re-sends it.</summary>
    Task<Result> ReplayDeliveryAsync(Guid deliveryId, CancellationToken cancellationToken);
}

/// <summary>The register result: the new endpoint id, the raw secret (once), its display prefix, and when it was created.</summary>
public sealed record RegisteredWebhook(
    Guid Id, string Secret, string SecretPrefix, string Url, DateTimeOffset CreatedAt);

/// <summary>The rotate result: the new raw secret (once) and its display prefix.</summary>
public sealed record RotatedWebhookSecret(string Secret, string SecretPrefix);

/// <summary>A listed endpoint: never the secret or its ciphertext, only the display prefix.</summary>
public sealed record WebhookEndpointView(
    Guid Id,
    string Url,
    string Description,
    IReadOnlyList<string> EventTypes,
    bool Disabled,
    string SecretPrefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>A listed delivery: the delivery log row shape (never the payload body or the secret).</summary>
public sealed record WebhookDeliveryView(
    Guid Id,
    Guid EndpointId,
    Guid EventId,
    string EventType,
    string Status,
    int Attempts,
    DateTimeOffset NextAttemptAt,
    DateTimeOffset? DeliveredAt,
    DateTimeOffset? DeadLetteredAt,
    int? LastResponseStatus,
    string? LastError,
    DateTimeOffset CreatedAt);
