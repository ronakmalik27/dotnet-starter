using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Starter.Identity.GoogleSignIn;
using Starter.Identity.Login;
using Starter.Identity.Passwords;
using Starter.Identity.Refresh;
using Starter.Identity.Register;
using Starter.Identity.SetPassword;
using Starter.Identity.Tokens;
using Starter.Identity.Verification;
using Starter.Platform.Data;

namespace Starter.Identity;

/// <summary>
/// The Identity module's bootstrap surface (ADR-0011, LLD section 1): the
/// single public entry the composition root calls. Owns accounts, tokens,
/// sessions, consent, and profiles; the register / login / refresh slices
/// landed with #33 and the email-verification slices with #34, the rest
/// join with stories #35-#40.
/// </summary>
public static class IdentityModule
{
    /// <summary>
    /// Registers the module. <paramref name="signingKey"/> is the ES256
    /// access-token key (doc 10 4.2); the composition root owns where it
    /// comes from (Key Vault in production, dev-only key locally - doc 10
    /// section 9) and hands the same key to the platform's JWT
    /// verification, so issuer and verifier can never disagree.
    /// <paramref name="configuration"/> carries the Auth:Google OIDC
    /// section (doc 10 4.5; client secret via user-secrets/Key Vault,
    /// doc 10 section 9); when null or absent, Google sign-in answers 501
    /// and everything else works.
    /// </summary>
    public static IServiceCollection AddIdentityModule(
        this IServiceCollection services,
        string connectionString,
        ECDsaSecurityKey signingKey,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);

        services.AddModuleDbContext<IdentityDbContext>(IdentityDbContext.SchemaName, connectionString);

        services.AddSingleton(new AccessTokenIssuer(signingKey));
        services.AddSingleton<BreachedPasswordSet>();
        services.AddSingleton<PasswordPolicy>();

        // Google OIDC (#35): discovery metadata is a caching singleton;
        // the code exchange rides a typed HttpClient (factory-managed
        // handler lifetimes).
        if (configuration is not null)
        {
            services.Configure<GoogleOidcOptions>(configuration.GetSection(GoogleOidcOptions.SectionName));
        }
        else
        {
            services.AddOptions<GoogleOidcOptions>();
        }

        services.AddHttpClient(GoogleOidcMetadata.HttpClientName);
        services.AddSingleton<GoogleOidcMetadata>();
        services.AddHttpClient<GoogleCodeExchanger>();
        services.AddScoped<GoogleIdTokenValidator>();

        services.AddScoped<SessionIssuer>();
        services.AddScoped<RegisterHandler>();
        services.AddScoped<LoginHandler>();
        services.AddScoped<RefreshHandler>();
        services.AddScoped<GoogleSignInHandler>();
        services.AddScoped<SetPasswordHandler>();
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<VerificationStatusHandler>();
        services.AddScoped<ResendVerificationHandler>();
        services.AddScoped<VerifiedEmailQuery>();
        services.AddScoped<IIdentityApi, IdentityApi>();

        return services;
    }
}
