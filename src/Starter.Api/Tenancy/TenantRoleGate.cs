using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Tenancy;

/// <summary>
/// The RBAC capability gate (multi-tenancy.md section 5, layer 2): an endpoint
/// filter that 403s any authenticated caller whose role in the ACTIVE tenant is
/// below the minimum the endpoint requires, with the stable
/// starter:tenant-role-required problem. It is the exact idiom of
/// RequireVerifiedEmail / RequireTenant - resolve per-request state via a module
/// API on http.RequestServices and return a problem - so the tenant-role layer
/// is an endpoint filter, while resource ownership stays in IAuthorizationService
/// (the layer-3 handler). Compose it AFTER RequireTenant so a request with no
/// resolved tenant gets 400 tenant-required, not a 403 here; fail-closed on a
/// missing or unparseable sub (401) and on no active membership (403).
/// </summary>
public static class TenantRoleGate
{
    /// <summary>Declares the endpoint's minimum tenant role (owner &gt; admin &gt; member).</summary>
    public static TBuilder RequireTenantRole<TBuilder>(this TBuilder builder, TenantRole minimum)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeAsync(invocationContext, next, minimum));
    }

    private static async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        TenantRole minimum)
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
        var role = await tenancy.GetCallerRoleAsync(userId.Value, http.RequestAborted);
        if (role is not { } tenantRole || tenantRole < minimum)
        {
            return TypedResults.Problem(StarterProblems.TenantRoleRequired(http));
        }

        return await next(context);
    }
}
