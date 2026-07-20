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
        services.AddAuthorization();
        return services;
    }
}
