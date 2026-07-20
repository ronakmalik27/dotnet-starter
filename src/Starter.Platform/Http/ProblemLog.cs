using Microsoft.Extensions.Logging;

namespace Starter.Platform.Http;

/// <summary>
/// Source-generated log messages for the problem mapper (CA1848). The
/// exception rides the structured Exception slot; request bodies and other
/// sensitive denylist material are never logged here.
/// </summary>
internal static partial class ProblemLog
{
    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled exception mapped to problem+json 500 (traceId {TraceId}).")]
    public static partial void UnhandledException(ILogger logger, Exception exception, string traceId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled exception after the response started; the response aborts unmapped.")]
    public static partial void ResponseAlreadyStarted(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "Request rejected while reading it; mapped to problem+json {StatusCode} (traceId {TraceId}).")]
    public static partial void ClientRequestRejected(ILogger logger, Exception exception, string traceId, int statusCode);
}
