using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Auth.Conditions;
using Starter.Platform.Data;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

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

    /// <summary>
    /// Declares that the endpoint consumes a METERED usage quota (quotas.md section
    /// 5): the active tenant's plan limit for <paramref name="metric"/> is resolved,
    /// then <paramref name="amount"/> is reserved against it. If the reserve breaches
    /// the ceiling the request short-circuits with 429
    /// <c>starter:quota-exceeded</c> plus a <c>Retry-After</c> header of the whole
    /// seconds until the period reset; otherwise it proceeds.
    /// <para>
    /// Compose it LAST: AFTER <see cref="RequireTenant"/> (a no-tenant request answers
    /// 400 first), AFTER <see cref="RequirePermission"/> (an unauthorized caller gets
    /// 403 first), and AFTER any <see cref="RequireEntitlement"/> (a plan that omits
    /// the feature answers 402 first). Consuming a quota is the only WRITE in the
    /// chain, so every cheaper read-only rejection must run first, so a request that
    /// was always going to be rejected never burns a unit of the tenant's budget.
    /// </para>
    /// <para>
    /// A COMMERCIAL gate, so it FAILS OPEN: an absent limit means the metric is
    /// unlimited and the gate is a no-op (writes nothing). Enforcement engages only
    /// once an operator publishes a plan naming a finite limit; a limit of 0 is
    /// deny-all.
    /// </para>
    /// </summary>
    public static TBuilder RequireQuota<TBuilder>(this TBuilder builder, string metric, int amount = 1)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(metric);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeQuotaAsync(invocationContext, next, metric, amount));
    }

    /// <summary>
    /// Declares that the endpoint is gated by a FEATURE FLAG (feature-flags.md
    /// section 4): the flag must resolve ON for the active tenant, else the request
    /// short-circuits with 404 - a not-yet-released feature should look like it does
    /// not exist, not like it is forbidden or paywalled, so a probe cannot map the
    /// unreleased surface. Compose it AFTER <see cref="RequireTenant"/> (a no-tenant
    /// request answers 400 tenant-required first).
    /// <para>
    /// Feature flags FAIL CLOSED, so an unknown, archived, or off flag all resolve to
    /// 404. A flag gate and an entitlement gate are independent and may both apply;
    /// the flag's 404 hides the surface when both compose.
    /// </para>
    /// </summary>
    public static TBuilder RequireFeatureFlag<TBuilder>(this TBuilder builder, string flagKey)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(flagKey);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeFeatureFlagAsync(invocationContext, next, flagKey));
    }

    private static async ValueTask<object?> InvokeFeatureFlagAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        string flagKey)
    {
        var http = context.HttpContext;

        // A feature flag is a property of the ACTIVE tenant, not the caller (like an
        // entitlement). RequireTenant (composed before) guarantees a resolved tenant,
        // so the evaluator's RLS override read is bound to it. The workspace, when the
        // request is workspace-scoped, sharpens resolution (workspace override wins).
        var evaluator = http.RequestServices.GetRequiredService<IFeatureFlagEvaluator>();
        var workspace = http.RequestServices.GetRequiredService<IWorkspaceContext>();
        var enabled = await evaluator.IsEnabledAsync(flagKey, workspace.WorkspaceId, http.RequestAborted);
        if (!enabled)
        {
            // 404, not 403/402: a hidden feature looks absent. The idiomatic
            // starter:not-found envelope, the same the route 404 wears.
            return TypedResults.Problem(StarterProblems.ForStatus(http, StatusCodes.Status404NotFound));
        }

        return await next(context);
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

    private static async ValueTask<object?> InvokeQuotaAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next,
        string metric,
        int amount)
    {
        var http = context.HttpContext;

        // The limit is a property of the ACTIVE tenant's plan, resolved the same way
        // RequireEntitlement resolves the feature set. Read it with TryGetValue, NEVER
        // GetLimit (quotas.md section 5): GetLimit returns a non-nullable int and
        // cannot tell "absent" from "present-with-fallback", which would collapse an
        // absent limit into a deny-all 0 or a bogus unlimited. Absent -> null ->
        // unlimited (fail open); present -> the finite limit.
        var tenancy = http.RequestServices.GetRequiredService<ITenancyApi>();
        var entitlements = await tenancy.GetCallerEntitlementsAsync(http.RequestAborted);
        int? limit = entitlements.Limits.TryGetValue(metric, out var value) ? value : null;

        var quotas = http.RequestServices.GetRequiredService<IQuotaService>();
        var outcome = await quotas.TryConsumeAsync(metric, amount, limit, http.RequestAborted);
        if (!outcome.Allowed)
        {
            // Temporal refusal: name the whole seconds until the reset in Retry-After,
            // never negative (clamped at 0), so a client backs off exactly to the
            // period boundary. Set before returning the problem: the filter
            // short-circuits, so the response has not started and the header sticks.
            var clock = http.RequestServices.GetRequiredService<Clock>();
            var retryAfter = QuotaPeriod.RetryAfterSeconds(clock.UtcNow, outcome.ResetAt);
            http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);

            // A denied outcome always carries a finite limit (an unlimited metric
            // never denies), so the limit is non-null here.
            return TypedResults.Problem(
                StarterProblems.QuotaExceeded(http, metric, outcome.Limit ?? 0, outcome.ResetAt));
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

        // Tier 1: an unconditional grant confers it (unchanged). Tier 2 (the ABAC
        // seam, abac.md section 5) runs ONLY on a Tier-1 miss, so an RBAC-authorized
        // caller pays nothing; a genuine denial pays one extra RLS read. Fail closed.
        if (!permissions.Contains(permission)
            && !await ConditionalGrantAsync(http, userId.Value, principalType, permission, workspaceId: null))
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

        // Tier 1 then, on a miss, the ABAC Tier-2 seam scoped to this workspace: the
        // resolved workspaceId is passed both into the attribute bag and as the
        // scope argument (abac.md section 5). Fail closed.
        if (!permissions.Contains(permission)
            && !await ConditionalGrantAsync(http, userId.Value, principalType, permission, workspaceId))
        {
            return TypedResults.Problem(StarterProblems.PermissionRequired(http));
        }

        return await next(context);
    }

    /// <summary>
    /// The ABAC Tier-2 check (abac.md section 5), consulted only on a Tier-1
    /// (unconditional) miss: assembles the request-attribute bag from the injected
    /// <see cref="Clock"/> and the connection - layering the resolved workspace on
    /// for a workspace-scoped check - and asks the <see cref="IConditionalGrantResolver"/>
    /// whether a conditional grant confers <paramref name="permission"/> under those
    /// attributes. Fail-closed: the resolver returns false on no such grant, an
    /// unsatisfied condition, or any evaluation error.
    /// </summary>
    private static async ValueTask<bool> ConditionalGrantAsync(
        HttpContext http, Guid principalId, string principalType, string permission, Guid? workspaceId)
    {
        var clock = http.RequestServices.GetRequiredService<Clock>();
        var conditional = http.RequestServices.GetRequiredService<IConditionalGrantResolver>();
        var attributes = RequestAttributes.FromHttp(http, clock.UtcNow) with { WorkspaceId = workspaceId };
        return await conditional.IsGrantedAsync(
            principalId, principalType, permission, attributes, workspaceId, http.RequestAborted);
    }
}
