using Microsoft.Extensions.Logging;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Source-generated log messages for the delivery worker (CA1848). None of these ever
/// carries the receiver URL or the signing secret - only ids, statuses, and bounded
/// classifications.
/// </summary>
internal static partial class WebhookLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Webhook delivery worker acquired leadership.")]
    public static partial void LeadershipAcquired(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Webhook delivery worker lost leadership or failed; re-entering election.")]
    public static partial void LeadershipLost(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Webhook delivery {DeliveryId} failed (status {ResponseStatus}); attempt {Attempts}, will retry or dead-letter.")]
    public static partial void DeliveryFailed(ILogger logger, Guid deliveryId, int? responseStatus, int attempts);

    [LoggerMessage(Level = LogLevel.Error, Message = "Webhook delivery {DeliveryId} dead-lettered after {Attempts} attempts: {Reason}.")]
    public static partial void DeadLettered(ILogger logger, Guid deliveryId, int attempts, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Webhook delivery {DeliveryId} dropped at send time: its endpoint was deleted or disabled since fan-out.")]
    public static partial void EndpointGone(ILogger logger, Guid deliveryId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Webhook delivery {DeliveryId} could not decrypt its signing secret; dead-lettering (the DataProtection key ring is unavailable or rotated away).")]
    public static partial void SecretUnavailable(ILogger logger, Guid deliveryId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Webhook worker tick failed; skipping to the next poll.")]
    public static partial void TickFailed(ILogger logger, Exception exception);
}
