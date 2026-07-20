using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Starter.Platform.Http;

/// <summary>
/// The doc 08 section 1 envelope for framework-generated bare statuses:
/// route misses (404), method mismatches (405), content-type rejections
/// (415), authentication challenges (401), and body-binding failures the
/// framework answers with an empty 400. The standard StatusCodePages
/// middleware fires only for error responses that carry no body, so every
/// app-written problem document and every replayed idempotent response
/// passes through untouched. Registered right after
/// UseStarterProblemMapping (its xmldoc names the pairing).
/// </summary>
public static class StatusCodeProblems
{
    /// <summary>Writes the starter:* problem envelope on body-less 4xx/5xx responses.</summary>
    public static IApplicationBuilder UseStarterStatusCodeProblems(this IApplicationBuilder app) =>
        app.UseStatusCodePages(async statusCodeContext =>
        {
            var http = statusCodeContext.HttpContext;
            var serializerOptions = http.RequestServices
                .GetRequiredService<IOptions<JsonOptions>>().Value.SerializerOptions;
            var problem = StarterProblems.ForStatus(http, http.Response.StatusCode);
            await http.Response.WriteAsJsonAsync(
                problem,
                serializerOptions,
                contentType: "application/problem+json",
                http.RequestAborted);
        });
}
