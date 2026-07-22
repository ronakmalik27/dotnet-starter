using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Tenancy;

/// <summary>
/// The fine-grained RBAC capability gate (multi-tenancy.md section 13): an
/// endpoint filter that 403s any authenticated caller whose effective permission
/// set in the ACTIVE tenant does not include the required permission, with the
/// stable starter:permission-required problem. It is the exact idiom of
/// <see cref="TenantRoleGate"/> - resolve per-request state via
/// <see cref="ITenancyApi"/> on http.RequestServices and return a problem - so the
/// permission layer is an endpoint filter, exactly like the coarse tenant-role
/// layer. Compose it AFTER RequireTenant so a request with no resolved tenant
/// gets 400 tenant-required, not a 403 here; fail-closed on a missing or
/// unparseable sub (401) and on an absent permission (403).
/// </summary>
public static class PermissionGate
{
    /// <summary>Declares the endpoint's required permission (a catalogue key from Permissions).</summary>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, string permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeAsync(invocationContext, next, permission));
    }

    private static async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        string permission)
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
        var permissions = await tenancy.GetCallerPermissionsAsync(userId.Value, http.RequestAborted);
        if (!permissions.Contains(permission))
        {
            return TypedResults.Problem(StarterProblems.PermissionRequired(http));
        }

        return await next(context);
    }
}
