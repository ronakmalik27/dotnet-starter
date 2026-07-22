using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Paging;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the service-account control plane (service-accounts.md
/// sections 5, 7): create, list, rotate, and revoke, all over the ACTIVE tenant
/// (the singular /api/v1/tenant, resolved from the tid claim). Every route
/// requires a resolved tenant and an authenticated caller (group-level
/// RequireTenant + RequireAuthorization) and the api-keys:manage permission
/// (per-route RequirePermission). Business rules live behind
/// <see cref="ITenancyApi"/>; this layer shapes requests, transports, and the
/// problem envelope only. The raw key is returned ONCE at create and rotate and
/// never listed - the list carries only the display prefix.
/// </summary>
public static class ServiceAccountEndpoints
{
    public static IEndpointRouteBuilder MapServiceAccountEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var accounts = app.MapGroup("/api/v1/tenant/service-accounts")
            .RequireTenant()
            .RequireAuthorization();

        accounts.MapPost("/", CreateAsync).RequirePermission(Permissions.ApiKeysManage);
        accounts.MapGet("/", ListAsync).RequirePermission(Permissions.ApiKeysManage);
        accounts.MapPost("/{id:guid}/rotate", RotateAsync).RequirePermission(Permissions.ApiKeysManage);
        accounts.MapDelete("/{id:guid}", RevokeAsync).RequirePermission(Permissions.ApiKeysManage);

        return app;
    }

    private static async Task<IResult> CreateAsync(
        CreateServiceAccountRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["name"] = ["A service-account name is required."] }));
        }

        var result = await tenancy.CreateServiceAccountAsync(
            callerId.Value,
            request.Name!,
            request.ExpiresAt,
            request.RoleId,
            request.ScopeType,
            request.ScopeId,
            cancellationToken);
        return result.Match(
            created => (IResult)TypedResults.Created(
                (string?)null,
                new ServiceAccountCreatedResponse(
                    created.Id, created.RawKey, created.KeyPrefix, created.CreatedAt, created.ExpiresAt)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListAsync(
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken,
        int? limit = null,
        string? cursor = null)
    {
        var result = await tenancy.ListServiceAccountsAsync(PageLimit.Clamp(limit), cursor, cancellationToken);
        return result.Match(
            page => Results.Ok(new CursorPage<ServiceAccountResponse>(
                page.Items
                    .Select(account => new ServiceAccountResponse(
                        account.Id,
                        account.Name,
                        account.KeyPrefix,
                        account.CreatedAt,
                        account.LastUsedAt,
                        account.ExpiresAt,
                        account.RevokedAt))
                    .ToList(),
                page.NextCursor)),
            error => TenancyProblems.From(http, error));
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

        var result = await tenancy.RotateServiceAccountAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            rotated => Results.Ok(new RotateServiceAccountResponse(rotated.RawKey, rotated.KeyPrefix)),
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

        var result = await tenancy.RevokeServiceAccountAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>
/// POST /api/v1/tenant/service-accounts body: the account name, an optional expiry,
/// and an optional initial role to grant at create. When <paramref name="RoleId"/>
/// is set, <paramref name="ScopeType"/> is tenant | workspace (defaulting to
/// tenant) and <paramref name="ScopeId"/> is the workspace id for a workspace-scope
/// grant.
/// </summary>
public sealed record CreateServiceAccountRequest(
    string? Name, DateTimeOffset? ExpiresAt, Guid? RoleId, string? ScopeType, Guid? ScopeId);

/// <summary>
/// POST /api/v1/tenant/service-accounts success: the new account's id, the raw key
/// (returned ONCE, never retrievable again), its display prefix, and the timestamps.
/// </summary>
public sealed record ServiceAccountCreatedResponse(
    Guid Id, string Key, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt);

/// <summary>GET /api/v1/tenant/service-accounts item: never the secret or the hash, only the display prefix.</summary>
public sealed record ServiceAccountResponse(
    Guid Id,
    string Name,
    string KeyPrefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt);

/// <summary>POST /api/v1/tenant/service-accounts/{id}/rotate success: the new raw key (once) and its prefix.</summary>
public sealed record RotateServiceAccountResponse(string Key, string KeyPrefix);
