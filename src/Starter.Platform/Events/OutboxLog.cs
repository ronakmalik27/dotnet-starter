using Microsoft.Extensions.Logging;

namespace Starter.Platform.Events;

/// <summary>Source-generated log messages for the dispatcher (CA1848).</summary>
internal static partial class OutboxLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Outbox dispatcher acquired leadership.")]
    public static partial void LeadershipAcquired(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox dispatcher lost leadership or failed; re-entering election.")]
    public static partial void LeadershipLost(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Outbox row {EventId}/{Lane} poisoned after {Attempts} attempts ({EventType}).")]
    public static partial void Poisoned(ILogger logger, Guid eventId, string lane, int attempts, string eventType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox send failed for {EventId}/{Lane} ({EventType}); lease will redeliver.")]
    public static partial void SendFailed(ILogger logger, Exception exception, Guid eventId, string lane, string eventType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox row {EventId}/{Lane} has no registered consumer for {EventType} (consumer-registration skew); lease will redeliver until routing is restored or the row poisons.")]
    public static partial void Unroutable(ILogger logger, Guid eventId, string lane, string eventType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox delivered-mark failed for {EventId}/{Lane}; lease will redeliver.")]
    public static partial void MarkFailed(ILogger logger, Exception exception, Guid eventId, string lane);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox delivered-mark suppressed for {EventId}/{Lane}; the row was poisoned, already marked, or purged after the send started.")]
    public static partial void MarkSuppressed(ILogger logger, Guid eventId, string lane);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox lease re-arm matched no live row for {EventId}/{Lane}; skipping its send.")]
    public static partial void LeaseRowUnavailable(ILogger logger, Guid eventId, string lane);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Outbox {Lane} lane tick failed; skipping to the next poll.")]
    public static partial void TickFailed(ILogger logger, Exception exception, string lane);
}
