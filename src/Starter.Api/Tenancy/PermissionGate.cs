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

    /// <summary>
    /// Declares the endpoint's required plan FEATURE (billing-and-entitlements.md
    /// section 4): the caller's plan must include <paramref name="feature"/>, else
    /// the request short-circuits with 402 starter:payment-required. Compose it
    /// AFTER <see cref="RequirePermission"/> (permission-before-entitlement): a
    /// caller not even authorized for the feature gets a 403 and never learns
    /// whether the plan would have gated it (a 402 leaks that the feature exists
    /// behind a paywall). Composes after RequireTenant, so a no-tenant request
    /// answers 400 tenant-required first.
    /// <para>
    /// This is a COMMERCIAL gate, so it FAILS OPEN, unlike RequirePermission: an
    /// unrestricted plan (the default) passes every feature, so the filter is a
    /// no-op until an operator publishes a plan that restricts the feature.
    /// </para>
    /// </summary>
    public static TBuilder RequireEntitlement<TBuilder>(this TBuilder builder, string feature)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(feature);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeEntitlementAsync(invocationContext, next, feature));
    }

    private static async ValueTask<object?> InvokeEntitlementAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        string feature)
    {
        var http = context.HttpContext;

        // The entitlement is a property of the ACTIVE tenant's plan, not the caller,
        // so this reads the tenant's plan (resolved from the tid claim) - no userId
        // needed. RequireTenant (composed before) guarantees a resolved tenant.
        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        var entitlements = await tenancy.GetCallerEntitlementsAsync(http.RequestAborted);
        if (!entitlements.HasFeature(feature))
        {
            return TypedResults.Problem(StarterProblems.PaymentRequired(http));
        }

        return await next(context);
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

        // The caller's principal type from the pt claim (service-accounts.md
        // section 4), defaulting to user when absent - a JWT caller is a user, and
        // only the ApiKey scheme mints pt = service_account. The resolver then
        // takes the membership path for a user and the grants-only path for a
        // service account.
        var principalType = http.User.FindFirst(StarterClaims.Pt)?.Value ?? PrincipalTypes.User;

        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        var permissions = await tenancy.GetCallerPermissionsAsync(userId.Value, principalType, http.RequestAborted);
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

        var principalType = http.User.FindFirst(StarterClaims.Pt)?.Value ?? PrincipalTypes.User;

        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        var permissions = await tenancy.GetCallerPermissionsAsync(
            userId.Value, workspaceId, principalType, http.RequestAborted);
        if (!permissions.Contains(permission))
        {
            return TypedResults.Problem(StarterProblems.PermissionRequired(http));
        }

        return await next(context);
    }
}
