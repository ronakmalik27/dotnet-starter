using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Starter.Platform.Auth;

namespace Starter.Platform.Tenancy;

/// <summary>
/// Resolves the active tenant into the request-scoped <see cref="ITenantContext"/>
/// from the configured sources, in order (see <see cref="TenantResolutionOptions"/>).
/// It never rejects a request: an endpoint that needs a tenant enforces that
/// itself with <c>RequireTenant()</c> (400 <c>starter:tenant-required</c>), so
/// the anonymous and non-tenant surfaces keep working. Runs after
/// authentication (the <c>tid</c> claim is read off the signed principal).
/// <para>
/// This increment resolves a tenant only from a supplied id (a Guid): the
/// <c>tid</c> claim or a header/label carrying an id. A human slug (subdomain
/// or path) is recorded for observability but cannot map to an id until the
/// tenants table lands, so a slug-only request stays unresolved and fails
/// closed at the endpoint. There is no membership check here - that arrives
/// with the memberships table.
/// </para>
/// </summary>
public sealed class TenantResolutionMiddleware(RequestDelegate next, IOptions<TenantResolutionOptions> options)
{
    private const string PathPrefix = "/t/";

    private readonly TenantResolutionOptions _options = options.Value;

    // Injects the public ITenantContext (the scoped instance) and casts to the
    // concrete setter type; the DI registration guarantees they are the same
    // object. A public parameter keeps the middleware convention satisfied
    // without widening the mutable context's surface.
    public Task InvokeAsync(HttpContext context, ITenantContext tenantContextView)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(tenantContextView);

        var tenantContext = (TenantContext)tenantContextView;
        string? firstSlug = null;
        foreach (var source in _options.Order)
        {
            var token = Extract(source, context);
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            if (Guid.TryParse(token, out var tenantId) && tenantId != Guid.Empty)
            {
                // A resolvable id: it wins over any slug seen earlier.
                tenantContext.Resolve(tenantId, firstSlug);
                return next(context);
            }

            // A slug this increment cannot map to an id: remember the first
            // one, keep looking for a later source that yields an id.
            firstSlug ??= token;
        }

        if (firstSlug is not null)
        {
            tenantContext.RecordUnmappedSlug(firstSlug);
        }

        return next(context);
    }

    private string? Extract(TenantSource source, HttpContext context) => source switch
    {
        TenantSource.Claim => context.User.FindFirst(StarterClaims.Tid)?.Value,
        TenantSource.Subdomain => SubdomainLabel(context.Request.Host.Host),
        TenantSource.Path => PathSlug(context.Request.Path),
        TenantSource.Header => HeaderValue(context),
        _ => null,
    };

    private string? HeaderValue(HttpContext context) =>
        context.Request.Headers.TryGetValue(_options.HeaderName, out var values)
            && !string.IsNullOrWhiteSpace(values)
                ? values.ToString()
                : null;

    private static string? SubdomainLabel(string host)
    {
        // Only a genuine subdomain (three or more labels, e.g.
        // acme.app.example.com) yields a label; a bare apex or a host with no
        // dots (localhost) has none. An IP literal has no meaningful label.
        if (string.IsNullOrEmpty(host) || System.Net.IPAddress.TryParse(host, out _))
        {
            return null;
        }

        var firstDot = host.IndexOf('.', StringComparison.Ordinal);
        if (firstDot <= 0)
        {
            return null;
        }

        var labelsAfterFirst = host.Count(character => character == '.');
        return labelsAfterFirst >= 2 ? host[..firstDot] : null;
    }

    private static string? PathSlug(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value) || !value.StartsWith(PathPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var rest = value[PathPrefix.Length..];
        var end = rest.IndexOf('/', StringComparison.Ordinal);
        var slug = end < 0 ? rest : rest[..end];
        return string.IsNullOrWhiteSpace(slug) ? null : slug;
    }
}

/// <summary>Pipeline registration for <see cref="TenantResolutionMiddleware"/>.</summary>
public static class TenantResolutionApplicationBuilderExtensions
{
    /// <summary>
    /// Adds tenant resolution. Register it after UseAuthentication (so the
    /// <c>tid</c> claim is available) and before endpoint execution (so the
    /// request-scoped tenant is set before any handler opens a transaction).
    /// </summary>
    public static IApplicationBuilder UseStarterTenantResolution(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<TenantResolutionMiddleware>();
    }
}
