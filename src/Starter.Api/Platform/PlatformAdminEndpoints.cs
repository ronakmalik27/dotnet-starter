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

/// <summary>GET /api/v1/platform/admins item.</summary>
public sealed record PlatformAdminResponse(Guid UserId, Guid? GrantedBy, DateTimeOffset GrantedAt);

/// <summary>POST /api/v1/platform/admins body: a user id or an email (at least one).</summary>
public sealed record GrantAdminRequest(Guid? UserId, string? Email);

/// <summary>POST /api/v1/platform/impersonation body.</summary>
public sealed record StartImpersonationRequest(Guid TenantId, Guid? UserId, string? Reason);

/// <summary>POST /api/v1/platform/impersonation success: the grant id and the short access token.</summary>
public sealed record ImpersonationResponse(Guid GrantId, string AccessToken, int AccessTokenExpiresIn);
