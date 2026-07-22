using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Platform;

/// <summary>
/// The platform super-admin gate (multi-tenancy.md section 7): an endpoint
/// filter that 403s any authenticated caller who is not a platform super-admin,
/// with the stable starter:platform-admin-required problem. It is the exact
/// idiom of RequireTenantRole / RequireVerifiedEmail - resolve per-request state
/// via a module API on http.RequestServices and return a stable problem - but it
/// keys on platform.platform_admins (through ITenancyApi), NEVER a tenant role:
/// platform power is separate from tenant membership by design. Fail closed on a
/// missing or unparseable sub (401) and on a non-admin caller (403).
/// </summary>
public static class PlatformAdminGate
{
    /// <summary>Declares the endpoint platform-super-admin only.</summary>
    public static TBuilder RequirePlatformAdmin<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeAsync(invocationContext, next));
    }

    private static async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var http = context.HttpContext;

        // RequireAuthorization already ran for a correctly-composed endpoint;
        // this guard makes the gate itself fail closed if it is composed onto an
        // anonymous route by mistake.
        var userId = http.User.GetUserId();
        if (userId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        if (!await tenancy.IsPlatformAdminAsync(userId.Value, http.RequestAborted))
        {
            return TypedResults.Problem(StarterProblems.PlatformAdminRequired(http));
        }

        return await next(context);
    }
}
