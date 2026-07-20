using Microsoft.Extensions.Logging;

namespace Starter.Platform.Http;

/// <summary>
/// Source-generated log messages for the idempotency filter (CA1848).
/// Keys and endpoints only - never request bodies or stored responses.
/// </summary>
internal static partial class IdempotencyLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Idempotent replay served for {Endpoint} (key {Key}).")]
    public static partial void Replayed(ILogger logger, string endpoint, Guid key);

    [LoggerMessage(Level = LogLevel.Information, Message = "In-flight duplicate rejected for {Endpoint} (key {Key}); 409 with Retry-After 1.")]
    public static partial void InFlightRejected(ILogger logger, string endpoint, Guid key);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Idempotency key {Key} reused across endpoints: stored for {StoredEndpoint}, sent to {RequestEndpoint}; 422.")]
    public static partial void EndpointMismatch(ILogger logger, Guid key, string storedEndpoint, string requestEndpoint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Idempotency filter reached without an authenticated caller on {Endpoint}; authentication must run before it.")]
    public static partial void MissingUser(ILogger logger, string endpoint);
}
