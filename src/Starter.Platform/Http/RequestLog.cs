using Microsoft.Extensions.Logging;

namespace Starter.Platform.Http;

/// <summary>
/// Source-generated log messages for the correlation/request-logging
/// middleware (CA1848). Never logs request bodies, headers, or query
/// strings - only the method, path, status, and elapsed time.
/// </summary>
internal static partial class RequestLog
{
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "HTTP {Method} {Path} responded {StatusCode} in {ElapsedMs} ms.")]
    public static partial void RequestCompleted(
        ILogger logger, string method, string path, int statusCode, long elapsedMs);
}
