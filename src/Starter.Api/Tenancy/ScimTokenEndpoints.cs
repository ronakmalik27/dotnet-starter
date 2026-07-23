using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Api.Platform;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the SCIM-token management surface (sso-and-scim.md section 5):
/// create, list, rotate, and revoke the per-tenant SCIM bearer, all over the ACTIVE
/// tenant (/api/v1/tenant/scim/tokens) and gated by RequirePermission(settings:manage)
/// - SCIM is part of the same enterprise-integration admin surface as the SSO config,
/// so no new permission atom. This is the standard JWT-authenticated admin plane; the
/// SCIM bearer it mints authenticates the SEPARATE /scim/v2 surface, never this one.
/// The raw token is returned ONCE at create and rotate and never listed - the list
/// carries only the display prefix. Business rules live behind
/// <see cref="ITenancyApi"/>; this layer shapes requests, transports, and the problem
/// envelope only.
/// <para>
/// Create and rotate are refused under an impersonation token
/// (<see cref="ImpersonationBlockGate.BlockUnderImpersonation{TBuilder}"/>): minting a
/// standing tenant bearer under an impersonated support session is a persistence
/// vector. List and revoke are not minting acts, so they are not blocked.
/// </para>
/// </summary>
public static class ScimTokenEndpoints
{
    public static IEndpointRouteBuilder MapScimTokenEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var tokens = app.MapGroup("/api/v1/tenant/scim/tokens")
            .RequireTenant()
            .RequireAuthorization();

        tokens.MapPost("/", CreateAsync)
            .RequirePermission(Permissions.SettingsManage)
            .BlockUnderImpersonation();
        tokens.MapGet("/", ListAsync).RequirePermission(Permissions.SettingsManage);
        tokens.MapPost("/{id:guid}/rotate", RotateAsync)
            .RequirePermission(Permissions.SettingsManage)
            .BlockUnderImpersonation();
        tokens.MapDelete("/{id:guid}", RevokeAsync).RequirePermission(Permissions.SettingsManage);

        return app;
    }

    private static async Task<IResult> CreateAsync(
        CreateScimTokenRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.CreateScimTokenAsync(callerId.Value, request.ExpiresAt, cancellationToken);
        return result.Match(
            created => (IResult)TypedResults.Created(
                (string?)null,
                new ScimTokenCreatedResponse(
                    created.Id, created.RawToken, created.TokenPrefix, created.CreatedAt, created.ExpiresAt)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListAsync(
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var tokens = await tenancy.ListScimTokensAsync(cancellationToken);
        var items = tokens
            .Select(token => new ScimTokenResponse(
                token.Id, token.TokenPrefix, token.CreatedAt, token.ExpiresAt, token.RevokedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> RotateAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.RotateScimTokenAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            rotated => Results.Ok(new RotateScimTokenResponse(rotated.RawToken, rotated.TokenPrefix)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> RevokeAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.RevokeScimTokenAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>POST /api/v1/tenant/scim/tokens body: an optional expiry (null means no expiry).</summary>
public sealed record CreateScimTokenRequest(DateTimeOffset? ExpiresAt);

/// <summary>
/// POST /api/v1/tenant/scim/tokens success: the new token's id, the raw token
/// (returned ONCE, never retrievable again), its display prefix, and the timestamps.
/// </summary>
public sealed record ScimTokenCreatedResponse(
    Guid Id, string Token, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt);

/// <summary>GET /api/v1/tenant/scim/tokens item: never the secret or the hash, only the display prefix.</summary>
public sealed record ScimTokenResponse(
    Guid Id, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt);

/// <summary>POST /api/v1/tenant/scim/tokens/{id}/rotate success: the new raw token (once) and its prefix.</summary>
public sealed record RotateScimTokenResponse(string Token, string TokenPrefix);
