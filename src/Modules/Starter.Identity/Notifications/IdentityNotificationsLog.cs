using Microsoft.Extensions.Logging;

namespace Starter.Identity.Notifications;

/// <summary>
/// Source-generated log messages for the notifications consumer (CA1848).
/// No PII: only the event id and event type appear, never the recipient
/// address or any credential material.
/// </summary>
internal static partial class IdentityNotificationsLog
{
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Notification event {EventType} has no user to notify (row gone); skipping.")]
    public static partial void UserGone(ILogger logger, string eventType);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Notification send failed for claimed event {EventId} ({EventType}); the notice is dropped.")]
    public static partial void SendFailed(ILogger logger, Exception exception, Guid eventId, string eventType);
}
