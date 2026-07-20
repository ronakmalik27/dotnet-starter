using Microsoft.AspNetCore.Http;

namespace Starter.Platform.Http;

/// <summary>
/// The replay path of LLD 7.2: writes the stored status and body verbatim
/// plus Idempotency-Replayed: true. A replayed body can be up to 14 days
/// old; the header is the client's cue to refetch any derived state it
/// renders next (doc 08 section 1).
/// </summary>
internal sealed class ReplayedIdempotentResult(int statusCode, string bodyJson)
    : IResult, IStatusCodeHttpResult
{
    /// <summary>The stored jsonb text for a body-less response.</summary>
    internal const string EmptyBody = "null";

    public int? StatusCode => statusCode;

    public async Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.Headers[IdempotencyHeaders.Replayed] = "true";
        if (bodyJson != EmptyBody)
        {
            httpContext.Response.ContentType = "application/json; charset=utf-8";
            await httpContext.Response.WriteAsync(bodyJson, httpContext.RequestAborted);
        }
    }
}
