using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the tenant feature-flag surface (feature-flags.md section 5),
/// all over the ACTIVE tenant (/api/v1/tenant/feature-flags) and gated by the
/// group-level RequireTenant + RequireAuthorization and per-route
/// RequirePermission(feature-flags:manage). The GET reports the tenant's RESOLVED
/// flags (with which are overridable); PUT sets and DELETE clears the tenant's own
/// tenant/workspace overrides. Business rules (RLS-bound resolve/set/clear, the
/// overridable gate) live behind the Platform-registered <see cref="IFeatureFlagAdmin"/>;
/// this layer shapes requests, transports, and the problem envelope only.
/// <para>
/// This file also maps the RequireFeatureFlag GATE DEMONSTRATION endpoint
/// (<see cref="MapFeatureFlagGateDemoEndpoints"/>): a single route gated by
/// RequireFeatureFlag("gate-demo") that a test enables (behind a config toggle) to
/// prove the filter fail-closes to 404. No existing endpoint is gated by default
/// (feature-flags.md section 4): the feature is demonstrated by tests, not by
/// retrofitting a live route, so the demo route maps ONLY when
/// <c>FeatureFlags:GateDemoEnabled</c> is set - never in production.
/// </para>
/// </summary>
public static class FeatureFlagEndpoints
{
    /// <summary>The flag key the demonstration endpoint is gated by (used by the fail-closed test).</summary>
    public const string GateDemoFlagKey = "gate-demo";

    /// <summary>The config key that maps the gate-demonstration endpoint (test host only).</summary>
    public const string GateDemoConfigKey = "FeatureFlags:GateDemoEnabled";

    public static IEndpointRouteBuilder MapTenantFeatureFlagEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var flags = app.MapGroup("/api/v1/tenant/feature-flags")
            .RequireTenant()
            .RequireAuthorization();

        flags.MapGet("/", ListAsync).RequirePermission(Permissions.FeatureFlagsManage);
        flags.MapPut("/{key}", SetAsync).RequirePermission(Permissions.FeatureFlagsManage);
        flags.MapDelete("/{key}", ClearAsync).RequirePermission(Permissions.FeatureFlagsManage);

        return app;
    }

    /// <summary>
    /// Maps the RequireFeatureFlag gate demonstration endpoint (feature-flags.md
    /// section 4). Registered ONLY when the caller opts in (the test host), so no
    /// live route is gated by default. The route returns 200 when the "gate-demo"
    /// flag is ON for the active tenant, and the filter fail-closes to 404 when the
    /// flag is unknown, archived, or off.
    /// </summary>
    public static IEndpointRouteBuilder MapFeatureFlagGateDemoEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet("/api/v1/tenant/feature-flag-gate-demo", GateDemoAsync)
            .RequireTenant()
            .RequireAuthorization()
            .RequireFeatureFlag(GateDemoFlagKey);

        return app;
    }

    private static async Task<IResult> ListAsync(
        IFeatureFlagAdmin flags,
        HttpContext http,
        CancellationToken cancellationToken,
        Guid? workspaceId = null)
    {
        var resolved = await flags.ListResolvedAsync(workspaceId, cancellationToken);
        var items = resolved
            .Select(flag => new FeatureFlagStateResponse(flag.Key, flag.Description, flag.Enabled, flag.Overridable))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> SetAsync(
        string key,
        SetFeatureFlagOverrideRequest request,
        IFeatureFlagAdmin flags,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var scopeType = string.IsNullOrWhiteSpace(request.ScopeType)
            ? FeatureFlagScopes.Tenant
            : request.ScopeType.Trim();

        var result = await flags.SetOverrideAsync(
            callerId.Value, key, request.Enabled, scopeType, request.ScopeId, cancellationToken);
        return result.Match(() => Results.NoContent(), error => Problem(http, error));
    }

    private static async Task<IResult> ClearAsync(
        string key,
        IFeatureFlagAdmin flags,
        HttpContext http,
        CancellationToken cancellationToken,
        string? scopeType = null,
        Guid? scopeId = null)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var scope = string.IsNullOrWhiteSpace(scopeType) ? FeatureFlagScopes.Tenant : scopeType.Trim();

        var result = await flags.ClearOverrideAsync(callerId.Value, key, scope, scopeId, cancellationToken);
        return result.Match(() => Results.NoContent(), error => Problem(http, error));
    }

    private static IResult GateDemoAsync() => Results.Ok(new GateDemoResponse(true));

    // The overridable refusal is a dedicated 403 (a tenant cannot touch an
    // operator-held flag); every other code maps through the generic ErrorKind
    // table (NotFound -> 404, Validation -> 422).
    private static IResult Problem(HttpContext http, Error error) => error.Code switch
    {
        "tenancy.flag_not_overridable" => TypedResults.Problem(StarterProblems.FlagNotOverridable(http)),
        _ => error.ToProblemResult(http),
    };
}

/// <summary>GET /api/v1/tenant/feature-flags item: a resolved flag and whether the tenant may override it.</summary>
public sealed record FeatureFlagStateResponse(string Key, string Description, bool Enabled, bool Overridable);

/// <summary>
/// PUT /api/v1/tenant/feature-flags/{key} body: the override value, and the scope
/// (<c>tenant</c> by default, or <c>workspace</c> with a <paramref name="ScopeId"/>).
/// </summary>
public sealed record SetFeatureFlagOverrideRequest(bool Enabled, string? ScopeType, Guid? ScopeId);

/// <summary>GET /api/v1/tenant/feature-flag-gate-demo success body (the gate demonstration).</summary>
public sealed record GateDemoResponse(bool Ok);
