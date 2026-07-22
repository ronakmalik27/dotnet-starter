using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// The fine-grained RBAC capability gate (multi-tenancy.md section 13): an
/// endpoint filter that 403s any authenticated caller whose effective permission
/// set does not include the required permission, with the stable
/// starter:permission-required problem. It is the exact idiom of
/// <see cref="TenantRoleGate"/> - resolve per-request state via
/// <see cref="ITenancyApi"/> on http.RequestServices and return a problem - so the
/// permission layer is an endpoint filter, exactly like the coarse tenant-role
/// layer.
/// <para>
/// Two forms. <see cref="RequirePermission"/> resolves at TENANT scope; compose
/// it AFTER RequireTenant so a request with no resolved tenant gets 400
/// tenant-required, not a 403 here. <see cref="RequireWorkspacePermission"/>
/// resolves at the WORKSPACE named by the <c>{workspaceId}</c> route segment
/// (union of tenant-scope and that workspace's grants); compose it AFTER
/// RequireWorkspace so a bad workspace is 404 workspace-not-found, not a 403 here.
/// Both fail closed on a missing or unparseable sub (401) and on an absent
/// permission (403).
/// </para>
/// </summary>
public static class PermissionGate
{
    /// <summary>Declares the endpoint's required permission at TENANT scope (a catalogue key from Permissions).</summary>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, string permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeAsync(invocationContext, next, permission));
    }

    /// <summary>
    /// Declares the endpoint's required permission AT THE WORKSPACE named by the
    /// <c>{workspaceId}</c> route segment. The caller passes if the permission is
    /// in their tenant-scope set (downward inheritance) OR in that workspace's
    /// grants. Compose after RequireWorkspace.
    /// </summary>
    public static TBuilder RequireWorkspacePermission<TBuilder>(this TBuilder builder, string permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeWorkspaceAsync(invocationContext, next, permission));
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

    private static async ValueTask<object?> InvokeWorkspaceAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        string permission)
    {
        var http = context.HttpContext;

        var userId = http.User.GetUserId();
        if (userId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        // The workspace was validated and bound by the RequireWorkspace gate
        // (composed before this one). Reading it from the resolved context ties
        // the permission check to the exact workspace that existence check
        // passed; if it is somehow unresolved, fail closed with 404 rather than
        // resolving a tenant-scope set that would wrongly admit the caller.
        var workspace = http.RequestServices.GetRequiredService<IWorkspaceContext>();
        if (workspace.WorkspaceId is not Guid workspaceId)
        {
            return TypedResults.Problem(StarterProblems.WorkspaceNotFound(http));
        }

        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        var permissions = await tenancy.GetCallerPermissionsAsync(userId.Value, workspaceId, http.RequestAborted);
        if (!permissions.Contains(permission))
        {
            return TypedResults.Problem(StarterProblems.PermissionRequired(http));
        }

        return await next(context);
    }
}
