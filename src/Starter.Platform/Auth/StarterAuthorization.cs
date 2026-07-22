using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Starter.Platform.Auth;

/// <summary>
/// The authorization half of the auth wiring: registers the resource-based
/// handlers and the authorization services. Called by
/// <see cref="StarterJwtAuthentication.AddStarterJwtAuthentication"/>, so a
/// host that adds Starter JWT authentication gets resource authorization with
/// it and needs no separate call.
/// </summary>
public static class StarterAuthorization
{
    /// <summary>
    /// Registers the resource-owner handler and the authorization services.
    /// Deliberately sets NO fallback policy that requires authentication: the
    /// anonymous surfaces (the auth endpoints, health probes, the OpenAPI
    /// document) must keep working, and authenticated endpoints opt in with
    /// RequireAuthorization. Resource-based checks then run per request
    /// through IAuthorizationService against the owned entity.
    /// </summary>
    public static IServiceCollection AddStarterAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Stateless, so a singleton: it holds no per-request state and reads
        // the caller's sub off the principal passed into each check.
        services.AddSingleton<IAuthorizationHandler, ResourceOwnerAuthorizationHandler>();

        // The tenant-admin resource layer (multi-tenancy.md section 5, layer 3):
        // an admin+ manages any resource in the active tenant. Scoped, because it
        // reads the caller's role through the request-scoped ITenantRoleReader
        // seam (bridged to the Tenancy module by the composition root). It runs
        // alongside the owner handler, so the effective rule is "owner OR
        // tenant-admin+".
        services.AddScoped<IAuthorizationHandler, TenantAdminResourceAuthorizationHandler>();
        services.AddAuthorization();
        return services;
    }
}
