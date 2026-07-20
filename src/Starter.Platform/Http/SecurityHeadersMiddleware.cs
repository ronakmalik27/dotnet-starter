using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Starter.Platform.Http;

/// <summary>
/// Adds the baseline response security headers to every response. It sits
/// outermost in the pipeline (outside the problem mapper) and registers its
/// writes through <see cref="HttpResponse.OnStarting(Func{object, Task}, object)"/>,
/// so they survive the problem mapper's <c>Response.Clear()</c> on an error
/// path. The CSP is <c>default-src 'none'</c>: an API serves JSON, not a
/// document with scripts or styles to load. Path prefixes in
/// <see cref="_exemptPathPrefixes"/> are skipped entirely - the composition
/// root passes the Development-only API-reference UI paths there so the
/// browser tool can still load its assets.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string[] _exemptPathPrefixes;

    public SecurityHeadersMiddleware(RequestDelegate next, IReadOnlyList<string> exemptPathPrefixes)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(exemptPathPrefixes);
        _next = next;
        _exemptPathPrefixes = [.. exemptPathPrefixes];
    }

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!IsExempt(context.Request.Path))
        {
            context.Response.OnStarting(static state =>
            {
                var headers = ((HttpContext)state).Response.Headers;
                headers["X-Content-Type-Options"] = "nosniff";
                headers["X-Frame-Options"] = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
                return Task.CompletedTask;
            }, context);
        }

        return _next(context);
    }

    private bool IsExempt(PathString path)
    {
        foreach (var prefix in _exemptPathPrefixes)
        {
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Pipeline registration for <see cref="SecurityHeadersMiddleware"/>.</summary>
public static class SecurityHeadersApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the baseline security headers. Register it outermost, before the
    /// problem mapper. <paramref name="exemptPathPrefixes"/> lists paths that
    /// get no headers (the Development-only API-reference UI); pass none in
    /// production.
    /// </summary>
    public static IApplicationBuilder UseStarterSecurityHeaders(
        this IApplicationBuilder app,
        params string[] exemptPathPrefixes)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SecurityHeadersMiddleware>((IReadOnlyList<string>)exemptPathPrefixes);
    }
}
