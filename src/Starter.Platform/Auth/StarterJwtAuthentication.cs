using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Starter.Platform.Auth;

/// <summary>
/// The verification half of the token design, positioned as the
/// authentication pipeline stage. Verification is local:
/// signature plus claims against a static key, never a per-request DB or
/// cache lookup. The `ver` claim is deliberately NOT checked
/// here - it is enforced at refresh only; the named
/// sensitive-read exceptions add their own live session check in their own
/// flows.
/// </summary>
public static class StarterJwtAuthentication
{
    /// <summary>
    /// Registers JWT bearer authentication over the given ES256 key. The
    /// key carries at least the public half; the composition root decides
    /// where it comes from (a managed secret store in production, dev-only
    /// user-secrets or ephemeral locally).
    /// </summary>
    public static IServiceCollection AddStarterJwtAuthentication(
        this IServiceCollection services,
        ECDsaSecurityKey signingKey)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(signingKey);

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // Keep the raw JWT claim names (sub/sid/ver); the legacy
                // SOAP-era claim-type mapping would rename sub and hide the
                // token contract from downstream readers.
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = StarterAuth.Issuer,
                    ValidAudience = StarterAuth.Audience,
                    IssuerSigningKey = signingKey,
                    // ES256 only: a token offering any other
                    // algorithm - including alg=none - fails before
                    // signature checking.
                    ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = StarterAuth.ClockSkew,
                    NameClaimType = StarterClaims.Sub,
                };
            });
        services.AddStarterAuthorization();
        return services;
    }
}
