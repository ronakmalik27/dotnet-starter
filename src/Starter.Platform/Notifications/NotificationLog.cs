using Microsoft.Extensions.Logging;

namespace Starter.Platform.Notifications;

/// <summary>
/// Source-generated log messages for the notification transports (CA1848).
/// </summary>
internal static partial class NotificationLog
{
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Email (console transport) to {To} - subject: {Subject}\n{TextBody}")]
    public static partial void ConsoleEmail(ILogger logger, string to, string subject, string textBody);
}
