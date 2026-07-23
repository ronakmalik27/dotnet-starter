using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace Starter.Api.Auth;

/// <summary>
/// Adds the additive non-JWT authentication schemes ALONGSIDE the JWT bearer scheme,
/// without changing the JWT path: the service-account <c>ApiKey</c> scheme
/// (service-accounts.md section 3) and the <c>Scim</c> bearer scheme (sso-and-scim.md
/// section 5). Call it from the composition root RIGHT AFTER
/// AddStarterJwtAuthentication, so the additive-scheme wiring lives in one named
/// method rather than scattered inline.
/// <para>
/// It registers the <c>ApiKey</c> and <c>Scim</c> schemes and a forwarding POLICY
/// scheme, then makes the policy scheme the default authenticate and challenge
/// scheme. The policy scheme's <c>ForwardDefaultSelector</c> routes a request to:
/// <c>Scim</c> when it carries a <c>Bearer scim_...</c> AND its path is under
/// <c>/scim/v2</c> (BOTH conditions - the CRITICAL confinement: a <c>scim_</c> bearer
/// on any other path is NOT routed to Scim, so it falls through to JWT and gets a
/// 401); <c>ApiKey</c> when it carries <c>Bearer sk_...</c> or <c>X-Api-Key</c>; and
/// <c>Bearer</c> (JWT) otherwise. Its <c>ForwardChallenge</c> stays <c>Bearer</c>, so
/// an unauthenticated request to a protected endpoint still gets the JWT scheme's
/// 401, unchanged. No authorization fallback policy is added (the existing design
/// deliberately has none, so the anonymous surfaces - health, OpenAPI - stay open).
/// </para>
/// </summary>
public static class StarterApiKeyAuthentication
{
    /// <summary>Registers the ApiKey and Scim schemes and the forwarding policy scheme; see the type remarks.</summary>
    public static IServiceCollection AddStarterApiKeyAuthentication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services
            .AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationDefaults.ApiKeyScheme, displayName: null, configureOptions: _ => { })
            .AddScheme<AuthenticationSchemeOptions, ScimAuthenticationHandler>(
                ScimAuthenticationDefaults.ScimScheme, displayName: null, configureOptions: _ => { })
            .AddPolicyScheme(
                ApiKeyAuthenticationDefaults.PolicyScheme,
                displayName: ApiKeyAuthenticationDefaults.PolicyScheme,
                options =>
                {
                    options.ForwardDefaultSelector = context =>
                    {
                        // Scim is checked FIRST and with BOTH conditions (shape + path):
                        // only a scim_ bearer UNDER /scim/v2 reaches the Scim scheme. A
                        // scim_ bearer on any other path is not a SCIM request, so it
                        // falls through to JWT and gets a 401 - it never authenticates.
                        if (ScimCredential.IsScimRequest(context))
                        {
                            return ScimAuthenticationDefaults.ScimScheme;
                        }

                        return ApiKeyCredential.IsApiKeyRequest(context)
                            ? ApiKeyAuthenticationDefaults.ApiKeyScheme
                            : JwtBearerDefaults.AuthenticationScheme;
                    };

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
