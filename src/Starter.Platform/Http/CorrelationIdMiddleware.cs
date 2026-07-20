using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Starter.SharedKernel;

namespace Starter.Platform.Http;

/// <summary>
/// Correlation id plus request logging. It reads the inbound
/// <c>X-Correlation-ID</c> header (or mints a UUIDv7 through the SharedKernel
/// Ids helper when absent), pushes it into the logging scope so every log
/// line the request produces carries it, and echoes it back on the response
/// header via <see cref="HttpResponse.OnStarting(Func{object, Task}, object)"/>
/// so the echo survives the problem mapper's <c>Response.Clear()</c>. The
/// completion log line is skipped for the health probes - they fire on a
/// timer and would drown the log. Timing rides the SharedKernel Clock, never
/// Stopwatch (time flows through Clock).
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    public const string HeaderName = "X-Correlation-ID";

    private static readonly PathString[] LogExemptPaths = [new("/healthz"), new("/readyz")];

    public async Task InvokeAsync(HttpContext context, Clock clock)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(clock);

        var correlationId = context.Request.Headers.TryGetValue(HeaderName, out var inbound)
            && !string.IsNullOrWhiteSpace(inbound)
                ? inbound.ToString()
                : Ids.NewId(clock.UtcNow).ToString();

        context.Response.OnStarting(static state =>
        {
            var (http, id) = ((HttpContext, string))state;
            http.Response.Headers[HeaderName] = id;
            return Task.CompletedTask;
        }, (context, correlationId));

        var logCompletion = !IsLogExempt(context.Request.Path);
        var startedAt = clock.UtcNow;

        using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
        {
            await next(context);

            if (logCompletion)
            {
                var elapsedMs = (long)(clock.UtcNow - startedAt).TotalMilliseconds;
                RequestLog.RequestCompleted(
                    logger,
                    context.Request.Method,
                    context.Request.Path.Value ?? "/",
                    context.Response.StatusCode,
                    elapsedMs);
            }
        }
    }

    private static bool IsLogExempt(PathString path)
    {
        foreach (var exempt in LogExemptPaths)
        {
            if (path.StartsWithSegments(exempt, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Pipeline registration for <see cref="CorrelationIdMiddleware"/>.</summary>
public static class CorrelationIdApplicationBuilderExtensions
{
    /// <summary>
    /// Adds correlation-id handling and request logging. Register it
    /// outermost, alongside the security headers and before the problem
    /// mapper, so every downstream log line carries the id.
    /// </summary>
    public static IApplicationBuilder UseStarterCorrelationId(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<CorrelationIdMiddleware>();
    }
}
