using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ProblemDetails = Microsoft.AspNetCore.Mvc.ProblemDetails;

namespace Starter.Platform.Http;

/// <summary>
/// The LLD section 1 problem+json error mapper: it wraps everything from
/// the endpoint filters inward, so no unhandled exception - a bug, per the
/// LLD's exceptions-are-for-bugs rule - ever reaches a client as anything
/// but the doc 08 envelope. The exception goes to the structured log with
/// the traceId that is also in the response body, so a client report can
/// be joined to the server-side stack trace.
/// </summary>
public sealed class ProblemMappingMiddleware(
    RequestDelegate next,
    PlatformHttpMetrics metrics,
    IOptions<JsonOptions> jsonOptions,
    ILogger<ProblemMappingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            await next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The client is gone; there is no response left to shape.
            throw;
        }
        catch (BadHttpRequestException exception)
        {
            // A client fault raised while reading the request (malformed
            // JSON body under ThrowOnBadRequest, oversized payload, ..):
            // the framework's status (400/413/431) is the truth - mapping
            // it to a 500 would misreport a client error as a server bug
            // (issue #105). Not counted as an unhandled exception.
            if (context.Response.HasStarted)
            {
                ProblemLog.ResponseAlreadyStarted(logger, exception);
                throw;
            }

            ProblemLog.ClientRequestRejected(logger, exception, context.TraceIdentifier, exception.StatusCode);
            await WriteProblemAsync(context, StarterProblems.BadRequest(context, exception.StatusCode));
        }
        catch (Exception exception)
        {
            if (context.Response.HasStarted)
            {
                // Too late to swap the body for a problem document; abort
                // the response rather than send a half-written payload.
                ProblemLog.ResponseAlreadyStarted(logger, exception);
                throw;
            }

            ProblemLog.UnhandledException(logger, exception, context.TraceIdentifier);
            metrics.UnhandledExceptionMapped();
            await WriteProblemAsync(context, StarterProblems.Internal(context));
        }
    }

    private async Task WriteProblemAsync(HttpContext context, ProblemDetails problem)
    {
        context.Response.Clear();
        context.Response.StatusCode = problem.Status!.Value;
        await context.Response.WriteAsJsonAsync(
            problem,
            jsonOptions.Value.SerializerOptions,
            contentType: "application/problem+json",
            context.RequestAborted);
    }
}

/// <summary>Pipeline registration for the problem mapper (LLD section 1).</summary>
public static class ProblemMappingApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the exception-to-problem+json mapper. LLD section 1 position:
    /// security headers and redacted logging register outside it, rate
    /// limiting and authentication inside it, and the endpoint filter chain
    /// (idempotency, authorization, validation) innermost. Register
    /// UseStarterStatusCodeProblems immediately after it: the two split the
    /// doc 08 envelope duty (exceptions here, framework-generated bare
    /// statuses there).
    /// </summary>
    public static IApplicationBuilder UseStarterProblemMapping(this IApplicationBuilder app) =>
        app.UseMiddleware<ProblemMappingMiddleware>();
}
