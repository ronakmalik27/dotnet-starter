using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Identity;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.SharedKernel;

namespace Starter.Api.Platform;

/// <summary>
/// HTTP composition for the platform super-admin plane (multi-tenancy.md section
/// 7): cross-tenant tenant lifecycle, the platform-admin roster, and audited
/// impersonation, all under /api/v1/platform. Every route requires an
/// authenticated caller who is a platform super-admin (group-level
/// RequireAuthorization + RequirePlatformAdmin), which is membership of
/// platform.platform_admins, NEVER a tenant role. These endpoints are NOT
/// tenant-scoped: they operate across tenants on the bypass path behind
/// <see cref="ITenancyApi"/>, and impersonation mints its token through
/// <see cref="IIdentityApi"/> AFTER the grant + audit event have committed - so
/// no impersonation token can exist without its audit row. Business rules live
/// behind the module APIs; this layer shapes requests, transports, and the
/// problem envelope only. BlockUnderImpersonation is deliberately absent here: a
/// platform admin managing impersonation is not acting under it.
/// </summary>
public static class PlatformAdminEndpoints
{
    public static IEndpointRouteBuilder MapPlatformAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var platform = app.MapGroup("/api/v1/platform")
            .RequireAuthorization()
            .RequirePlatformAdmin();

        platform.MapGet("/tenants", ListTenantsAsync);
        platform.MapGet("/tenants/{id:guid}", GetTenantAsync);
        platform.MapPost("/tenants/{id:guid}/suspend", SuspendTenantAsync);
        platform.MapPost("/tenants/{id:guid}/reactivate", ReactivateTenantAsync);
        platform.MapPost("/tenants/{id:guid}/delete", DeleteTenantAsync);
        platform.MapPost("/tenants/{id:guid}/erase", EraseTenantAsync);

        platform.MapGet("/plans", ListPlansAsync);
        platform.MapPost("/plans", CreatePlanAsync);
        platform.MapPatch("/plans/{key}", UpdatePlanAsync);
        platform.MapPost("/tenants/{id:guid}/plan", AssignPlanAsync);

        platform.MapGet("/feature-flags", ListFeatureFlagsAsync);
        platform.MapPost("/feature-flags", CreateFeatureFlagAsync);
        platform.MapPatch("/feature-flags/{key}", UpdateFeatureFlagAsync);

        platform.MapGet("/role-templates", ListRoleTemplatesAsync);
        platform.MapPost("/role-templates", CreateRoleTemplateAsync);
        platform.MapPatch("/role-templates/{key}", UpdateRoleTemplateAsync);
        platform.MapDelete("/role-templates/{key}", DeleteRoleTemplateAsync);
        platform.MapPost("/role-templates/{key}/seed", SeedRoleTemplateAsync);

        platform.MapGet("/policy-defaults", GetPolicyDefaultsAsync);
        platform.MapPatch("/policy-defaults", UpdatePolicyDefaultsAsync);

        platform.MapGet("/admins", ListAdminsAsync);
        platform.MapPost("/admins", GrantAdminAsync);
        platform.MapDelete("/admins/{userId:guid}", RevokeAdminAsync);

        platform.MapPost("/impersonation", StartImpersonationAsync);
        platform.MapPost("/impersonation/{id:guid}/end", EndImpersonationAsync);

        return app;
    }

    private static async Task<IResult> ListTenantsAsync(
        ITenancyApi tenancy,
        CancellationToken cancellationToken,
        string? query = null,
        int? limit = null)
    {
        var tenants = await tenancy.ListTenantsAsync(query, limit ?? 0, cancellationToken);
        var items = tenants
            .Select(t => new TenantSummaryResponse(t.Id, t.Slug, t.Name, t.Status, t.Plan, t.SeatLimit, t.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> GetTenantAsync(
        Guid id, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken)
    {
        var tenant = await tenancy.GetTenantAsync(id, cancellationToken);
        if (tenant is not { } t)
        {
            return TypedResults.Problem(StarterProblems.ForStatus(http, StatusCodes.Status404NotFound));
        }

        return Results.Ok(
            new TenantSummaryResponse(t.Id, t.Slug, t.Name, t.Status, t.Plan, t.SeatLimit, t.CreatedAt));
    }

    private static Task<IResult> SuspendTenantAsync(
        Guid id, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken) =>
        LifecycleAsync(http, (actor, ct) => tenancy.SuspendTenantAsync(actor, id, ct), cancellationToken);

    private static Task<IResult> ReactivateTenantAsync(
        Guid id, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken) =>
        LifecycleAsync(http, (actor, ct) => tenancy.ReactivateTenantAsync(actor, id, ct), cancellationToken);

    private static Task<IResult> DeleteTenantAsync(
        Guid id, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken) =>
        LifecycleAsync(http, (actor, ct) => tenancy.PlatformDeleteTenantAsync(actor, id, ct), cancellationToken);

    private static async Task<IResult> EraseTenantAsync(
        Guid id,
        EraseTenantRequest? request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        // The single most dangerous operation in the starter: one bypass transaction
        // that snapshots, purges, and audits (data-export-and-erasure.md section 5).
        // Returns the operator's pre-purge snapshot so it captures the compliance record.
        var result = await tenancy.EraseTenantAsync(actor.Value, id, request?.Force ?? false, cancellationToken);
        return result.Match(
            snapshot => (IResult)Results.Ok(snapshot),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> ListPlansAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var plans = await tenancy.ListPlansAsync(cancellationToken);
        var items = plans
            .Select(plan => new PlanResponse(
                plan.Key, plan.Name, plan.Features, plan.Permissions, plan.Limits, plan.IsDefault, plan.CreatedAt, plan.UpdatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> CreatePlanAsync(
        CreatePlanRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Key))
        {
            return Validation(http, "key", "A plan key is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Validation(http, "name", "A plan name is required.");
        }

        var result = await tenancy.CreatePlanAsync(
            actor.Value,
            request.Key,
            request.Name,
            request.Features,
            request.Permissions,
            request.Limits,
            request.IsDefault ?? false,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> UpdatePlanAsync(
        string key,
        UpdatePlanRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdatePlanAsync(
            actor.Value,
            key,
            request.Name,
            request.Features,
            request.Permissions,
            request.Limits,
            request.IsDefault,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> AssignPlanAsync(
        Guid id,
        AssignPlanRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Plan))
        {
            return Validation(http, "plan", "A plan key is required.");
        }

        var result = await tenancy.AssignPlanAsync(actor.Value, id, request.Plan, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> ListFeatureFlagsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var flags = await tenancy.ListFeatureFlagsAsync(cancellationToken);
        var items = flags
            .Select(flag => new FeatureFlagResponse(
                flag.Key,
                flag.Description,
                flag.DefaultEnabled,
                flag.RolloutPercentage,
                flag.TenantOverridable,
                flag.Archived,
                flag.CreatedAt,
                flag.UpdatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> CreateFeatureFlagAsync(
        CreateFeatureFlagRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Key))
        {
            return Validation(http, "key", "A flag key is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Description))
        {
            return Validation(http, "description", "A flag description is required.");
        }

        var result = await tenancy.CreateFeatureFlagAsync(
            actor.Value,
            request.Key,
            request.Description,
            request.DefaultEnabled ?? false,
            request.RolloutPercentage,
            request.TenantOverridable ?? false,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> UpdateFeatureFlagAsync(
        string key,
        UpdateFeatureFlagRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdateFeatureFlagAsync(
            actor.Value,
            key,
            request.Description,
            request.DefaultEnabled,
            request.RolloutPercentage,
            request.TenantOverridable,
            request.Archived,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> ListRoleTemplatesAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var templates = await tenancy.ListRoleTemplatesAsync(cancellationToken);
        var items = templates
            .Select(template => new RoleTemplateResponse(
                template.Key,
                template.Name,
                template.Description,
                template.Permissions,
                template.AssignableScopes,
                template.CreatedAt,
                template.UpdatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> CreateRoleTemplateAsync(
        CreateRoleTemplateRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Key))
        {
            return Validation(http, "key", "A role template key is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Validation(http, "name", "A role template name is required.");
        }

        var result = await tenancy.CreateRoleTemplateAsync(
            actor.Value,
            request.Key,
            request.Name,
            request.Description ?? string.Empty,
            request.Permissions ?? [],
            request.AssignableScopes ?? [],
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> UpdateRoleTemplateAsync(
        string key,
        UpdateRoleTemplateRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdateRoleTemplateAsync(
            actor.Value,
            key,
            request.Name,
            request.Description,
            request.Permissions,
            request.AssignableScopes,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> DeleteRoleTemplateAsync(
        string key, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.DeleteRoleTemplateAsync(actor.Value, key, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> SeedRoleTemplateAsync(
        string key,
        SeedRoleTemplateRequest? request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken,
        Guid? tenantId = null)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        // The target tenant may come from the body or a query parameter; a null
        // target seeds the template into every tenant.
        var target = request?.TenantId ?? tenantId;
        var result = await tenancy.SeedRoleTemplateAsync(actor.Value, key, target, cancellationToken);
        return result.Match(
            seeded => (IResult)Results.Ok(new SeedRoleTemplateResponse(seeded)),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> GetPolicyDefaultsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var policy = await tenancy.GetPolicyDefaultsAsync(cancellationToken);
        return Results.Ok(new PolicyDefaultsResponse(
            policy.PasswordMinLength,
            policy.AccessTokenLifetimeSeconds,
            policy.RefreshLifetimeSeconds,
            policy.LockoutMaxAttempts,
            policy.LockoutDurationSeconds));
    }

    private static async Task<IResult> UpdatePolicyDefaultsAsync(
        UpdatePolicyDefaultsRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdatePolicyDefaultsAsync(
            actor.Value,
            request.PasswordMinLength,
            request.AccessTokenLifetimeSeconds,
            request.RefreshLifetimeSeconds,
            request.LockoutMaxAttempts,
            request.LockoutDurationSeconds,
            cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> ListAdminsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var admins = await tenancy.ListPlatformAdminsAsync(cancellationToken);
        var items = admins
            .Select(admin => new PlatformAdminResponse(admin.UserId, admin.GrantedBy, admin.GrantedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> GrantAdminAsync(
        GrantAdminRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (request.UserId is null && string.IsNullOrWhiteSpace(request.Email))
        {
            return Validation(http, "userId", "A userId or email is required.");
        }

        var result = await tenancy.GrantPlatformAdminAsync(
            actor.Value, request.UserId, request.Email, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> RevokeAdminAsync(
        Guid userId, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.RevokePlatformAdminAsync(actor.Value, userId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> StartImpersonationAsync(
        StartImpersonationRequest request,
        ITenancyApi tenancy,
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (request.TenantId == Guid.Empty)
        {
            return Validation(http, "tenantId", "A target tenant id is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Reason))
        {
            return Validation(http, "reason", "A written reason is required.");
        }

        // Step 1: the Tenancy control plane writes the grant row and the
        // ImpersonationStarted event in one transaction (audit-before-token).
        var start = await tenancy.StartImpersonationAsync(
            actor.Value, request.TenantId, request.UserId, request.Reason, cancellationToken);
        if (start.IsFailure)
        {
            return PlatformAdminProblems.From(http, start.Error);
        }

        var grant = start.Value;

        // Step 2: mint the short impersonation token for the committed grant. If
        // this fails (a subject that went inactive), the grant simply expires
        // unused - the audit row still exists, which is the invariant that matters.
        var mint = await identity.IssueImpersonationTokenAsync(
            grant.SubjectUserId, grant.TargetTenantId, actor.Value, grant.GrantId, grant.ExpiresAt, cancellationToken);
        return mint.Match(
            token => (IResult)Results.Ok(
                new ImpersonationResponse(grant.GrantId, token.AccessToken, token.AccessTokenExpiresIn)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> EndImpersonationAsync(
        Guid id, ITenancyApi tenancy, HttpContext http, CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.EndImpersonationAsync(actor.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static async Task<IResult> LifecycleAsync(
        HttpContext http,
        Func<Guid, CancellationToken, Task<Result>> operation,
        CancellationToken cancellationToken)
    {
        var actor = http.User.GetUserId();
        if (actor is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await operation(actor.Value, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => PlatformAdminProblems.From(http, error));
    }

    private static ProblemHttpResult Validation(HttpContext http, string field, string message) =>
        TypedResults.Problem(StarterProblems.Validation(
            http, new Dictionary<string, string[]> { [field] = [message] }));
}

/// <summary>GET /api/v1/platform/tenants item and GET /api/v1/platform/tenants/{id} success.</summary>
public sealed record TenantSummaryResponse(
    Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt);

/// <summary>
/// GET /api/v1/platform/plans item (billing-and-entitlements.md section 7).
/// Null <paramref name="Features"/> / <paramref name="Permissions"/> means the
/// plan restricts nothing (unrestricted).
/// </summary>
public sealed record PlanResponse(
    string Key,
    string Name,
    IReadOnlyList<string>? Features,
    IReadOnlyList<string>? Permissions,
    IReadOnlyDictionary<string, int> Limits,
    bool IsDefault,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>
/// POST /api/v1/platform/plans body. Omit <paramref name="Features"/> /
/// <paramref name="Permissions"/> (or send null) for unrestricted;
/// <paramref name="Limits"/> MUST carry a positive seatLimit.
/// </summary>
public sealed record CreatePlanRequest(
    string? Key,
    string? Name,
    IReadOnlyList<string>? Features,
    IReadOnlyList<string>? Permissions,
    IReadOnlyDictionary<string, int>? Limits,
    bool? IsDefault);

/// <summary>PATCH /api/v1/platform/plans/{key} body. A null field leaves that facet unchanged.</summary>
public sealed record UpdatePlanRequest(
    string? Name,
    IReadOnlyList<string>? Features,
    IReadOnlyList<string>? Permissions,
    IReadOnlyDictionary<string, int>? Limits,
    bool? IsDefault);

/// <summary>POST /api/v1/platform/tenants/{id}/plan body: the plan key to assign.</summary>
public sealed record AssignPlanRequest(string? Plan);

/// <summary>
/// GET /api/v1/platform/feature-flags item (feature-flags.md section 5). Null
/// <paramref name="RolloutPercentage"/> means no rollout (the flag uses
/// <paramref name="DefaultEnabled"/>); <paramref name="Archived"/> true means the
/// flag resolves OFF and is hidden from the tenant surface.
/// </summary>
public sealed record FeatureFlagResponse(
    string Key,
    string Description,
    bool DefaultEnabled,
    int? RolloutPercentage,
    bool TenantOverridable,
    bool Archived,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>
/// POST /api/v1/platform/feature-flags body. Omit <paramref name="RolloutPercentage"/>
/// (or send null) for no rollout; a value must be 0..100.
/// </summary>
public sealed record CreateFeatureFlagRequest(
    string? Key,
    string? Description,
    bool? DefaultEnabled,
    int? RolloutPercentage,
    bool? TenantOverridable);

/// <summary>
/// PATCH /api/v1/platform/feature-flags/{key} body. A null field leaves that facet
/// unchanged; <paramref name="Archived"/> true archives, false unarchives, null leaves it.
/// </summary>
public sealed record UpdateFeatureFlagRequest(
    string? Description,
    bool? DefaultEnabled,
    int? RolloutPercentage,
    bool? TenantOverridable,
    bool? Archived);

/// <summary>
/// GET /api/v1/platform/role-templates item
/// (role-templates-and-policy-defaults.md section 2). <paramref name="Permissions"/>
/// and <paramref name="AssignableScopes"/> are exact sets, never "unrestricted".
/// </summary>
public sealed record RoleTemplateResponse(
    string Key,
    string Name,
    string Description,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> AssignableScopes,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>
/// POST /api/v1/platform/role-templates body. <paramref name="Permissions"/> are
/// catalogue atoms (none owner-reserved); <paramref name="AssignableScopes"/> is a
/// non-empty subset of {tenant, workspace}.
/// </summary>
public sealed record CreateRoleTemplateRequest(
    string? Key,
    string? Name,
    string? Description,
    IReadOnlyList<string>? Permissions,
    IReadOnlyList<string>? AssignableScopes);

/// <summary>PATCH /api/v1/platform/role-templates/{key} body. A null field leaves that facet unchanged.</summary>
public sealed record UpdateRoleTemplateRequest(
    string? Name,
    string? Description,
    IReadOnlyList<string>? Permissions,
    IReadOnlyList<string>? AssignableScopes);

/// <summary>
/// POST /api/v1/platform/role-templates/{key}/seed body. <paramref name="TenantId"/>
/// null (or the body omitted) seeds every tenant; a value seeds only that tenant. A
/// <c>tenantId</c> query parameter is an equivalent alternative.
/// </summary>
public sealed record SeedRoleTemplateRequest(Guid? TenantId);

/// <summary>POST /api/v1/platform/role-templates/{key}/seed success: how many tenants were newly seeded.</summary>
public sealed record SeedRoleTemplateResponse(int Seeded);

/// <summary>
/// GET /api/v1/platform/policy-defaults success
/// (role-templates-and-policy-defaults.md section 3): the install-wide password,
/// session, and lockout floors.
/// </summary>
public sealed record PolicyDefaultsResponse(
    int PasswordMinLength,
    int AccessTokenLifetimeSeconds,
    int RefreshLifetimeSeconds,
    int LockoutMaxAttempts,
    int LockoutDurationSeconds);

/// <summary>
/// PATCH /api/v1/platform/policy-defaults body. Every field is optional (a null
/// leaves that facet unchanged); a provided value is bounds-validated (positive,
/// sane maxima).
/// </summary>
public sealed record UpdatePolicyDefaultsRequest(
    int? PasswordMinLength,
    int? AccessTokenLifetimeSeconds,
    int? RefreshLifetimeSeconds,
    int? LockoutMaxAttempts,
    int? LockoutDurationSeconds);

/// <summary>GET /api/v1/platform/admins item.</summary>
public sealed record PlatformAdminResponse(Guid UserId, Guid? GrantedBy, DateTimeOffset GrantedAt);

/// <summary>POST /api/v1/platform/admins body: a user id or an email (at least one).</summary>
public sealed record GrantAdminRequest(Guid? UserId, string? Email);

/// <summary>
/// POST /api/v1/platform/tenants/{id}/erase body. <paramref name="Force"/> is the
/// documented break-glass for a legal erasure demand that cannot wait out the
/// retention window (data-export-and-erasure.md section 5); it defaults to false when
/// the body is omitted.
/// </summary>
public sealed record EraseTenantRequest(bool Force);

/// <summary>POST /api/v1/platform/impersonation body.</summary>
public sealed record StartImpersonationRequest(Guid TenantId, Guid? UserId, string? Reason);

/// <summary>POST /api/v1/platform/impersonation success: the grant id and the short access token.</summary>
public sealed record ImpersonationResponse(Guid GrantId, string AccessToken, int AccessTokenExpiresIn);
