using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace Starter.Api.Auth;

/// <summary>
/// Adds the API-key authentication scheme ALONGSIDE the JWT bearer scheme, without
/// changing the JWT path (service-accounts.md section 3). Call it from the
/// composition root RIGHT AFTER AddStarterJwtAuthentication, so the api-key wiring
/// lives in one named method rather than scattered inline.
/// <para>
/// It registers the <c>ApiKey</c> scheme (the <see cref="ApiKeyAuthenticationHandler"/>)
/// and a forwarding POLICY scheme, then makes the policy scheme the default
/// authenticate and challenge scheme. The policy scheme's <c>ForwardDefaultSelector</c>
/// routes an <c>Authorization: Bearer sk_...</c> or <c>X-Api-Key</c> request to
/// <c>ApiKey</c> and everything else to <c>Bearer</c> (JWT); its
/// <c>ForwardChallenge</c> stays <c>Bearer</c>, so an unauthenticated request to a
/// protected endpoint still gets the JWT scheme's 401, unchanged. No authorization
/// fallback policy is added (the existing design deliberately has none, so the
/// anonymous surfaces - health, OpenAPI - stay open).
/// </para>
/// </summary>
public static class StarterApiKeyAuthentication
{
    /// <summary>Registers the ApiKey scheme and the forwarding policy scheme; see the type remarks.</summary>
    public static IServiceCollection AddStarterApiKeyAuthentication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services
            .AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationDefaults.ApiKeyScheme, displayName: null, configureOptions: _ => { })
            .AddPolicyScheme(
                ApiKeyAuthenticationDefaults.PolicyScheme,
                displayName: ApiKeyAuthenticationDefaults.PolicyScheme,
                options =>
                {
                    options.ForwardDefaultSelector = context =>
                        ApiKeyCredential.IsApiKeyRequest(context)
                            ? ApiKeyAuthenticationDefaults.ApiKeyScheme
                            : JwtBearerDefaults.AuthenticationScheme;
                    // The challenge always forwards to JWT, so an unauthenticated
                    // request gets the JWT scheme's 401 unchanged.
                    options.ForwardChallenge = JwtBearerDefaults.AuthenticationScheme;
                });

        // Make the forwarding policy scheme the default (AddStarterJwtAuthentication
        // set the default to Bearer; this overrides it). DefaultAuthenticateScheme
        // wins over DefaultScheme, so UseAuthentication and the authorization
        // middleware authenticate through the selector.
        services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultAuthenticateScheme = ApiKeyAuthenticationDefaults.PolicyScheme;
            options.DefaultChallengeScheme = ApiKeyAuthenticationDefaults.PolicyScheme;
        });

        return services;
    }
}
