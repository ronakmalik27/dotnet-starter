using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Starter.Identity.ChangePassword;
using Starter.Identity.GoogleSignIn;
using Starter.Identity.Login;
using Starter.Identity.Notifications;
using Starter.Identity.PasswordReset;
using Starter.Identity.Passwords;
using Starter.Identity.Refresh;
using Starter.Identity.Register;
using Starter.Identity.SetPassword;
using Starter.Identity.Tokens;
using Starter.Identity.Verification;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;

namespace Starter.Identity;

/// <summary>
/// The Identity module's bootstrap surface: the single public entry the
/// composition root calls. Owns accounts, credentials, tokens, sessions,
/// and email verification.
/// </summary>
public static class IdentityModule
{
    /// <summary>
    /// Registers the module. <paramref name="signingKey"/> is the ES256
    /// access-token key; the composition root owns where it
    /// comes from (a managed secret store in production, a dev-only key locally) and
    /// hands the same key to the platform's JWT
    /// verification, so issuer and verifier can never disagree.
    /// <paramref name="configuration"/> carries the Auth:Google OIDC
    /// section (client secret via user-secrets or a managed secret store); when null or
    /// absent, Google sign-in answers 501
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

        // Google OIDC: discovery metadata is a caching singleton;
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

        // The verify-email link template (Auth:Verification) and the
        // password-reset link template (Auth:PasswordReset). Both guarded
        // for a null configuration exactly like the Google options above:
        // the module still boots with the default templates. Both are
        // validated options - the data annotation ([Required]) plus the
        // custom {token}-placeholder rule below, checked at startup
        // (ValidateOnStart). The defaults satisfy both, so a zero-config
        // host still boots.
        var verification = services.AddOptions<VerificationEmailOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        var passwordReset = services.AddOptions<PasswordResetEmailOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configuration is not null)
        {
            verification.Bind(configuration.GetSection(VerificationEmailOptions.SectionName));
            passwordReset.Bind(configuration.GetSection(PasswordResetEmailOptions.SectionName));
        }

        // One custom validator, richer than the annotations, covering both
        // link templates: each must carry the {token} placeholder. Registered
        // as an IValidateOptions for each type so ValidateOnStart runs it.
        services.AddSingleton<IValidateOptions<VerificationEmailOptions>, EmailLinkTemplateValidator>();
        services.AddSingleton<IValidateOptions<PasswordResetEmailOptions>, EmailLinkTemplateValidator>();

        services.AddScoped<VerificationEmailComposer>();
        services.AddScoped<PasswordResetEmailComposer>();

        services.AddScoped<SessionIssuer>();
        services.AddScoped<RegisterHandler>();
        services.AddScoped<RegistrationStagingHandler>();
        services.AddScoped<IssueSessionForHandler>();
        services.AddScoped<SelectTenantHandler>();
        services.AddScoped<LoginHandler>();
        services.AddScoped<RefreshHandler>();
        services.AddScoped<GoogleSignInHandler>();
        services.AddScoped<SetPasswordHandler>();
        services.AddScoped<ChangePasswordHandler>();
        services.AddScoped<RequestPasswordResetHandler>();
        services.AddScoped<ResetPasswordHandler>();
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<VerificationStatusHandler>();
        services.AddScoped<ResendVerificationHandler>();
        services.AddScoped<VerifiedEmailQuery>();
        services.AddScoped<UserDirectoryQuery>();
        services.AddScoped<IIdentityApi, IdentityApi>();

        // Bridge the platform-declared ports to the same IIdentityApi instance,
        // so the consumers depend on the ports (never on this module) and there
        // is one implementation with no drift.
        services.AddScoped<ITenantProvisioningIdentity>(
            provider => provider.GetRequiredService<IIdentityApi>());
        services.AddScoped<IUserDirectory>(
            provider => provider.GetRequiredService<IIdentityApi>());

        // The account-security notifications consumer. Singleton and
        // singleton-safe (it resolves the scoped context per consume). Only
        // registered with persistence, since AddIdentityModule is composed
        // inside the composition root's postgres block.
        services.AddSingleton<IDomainEventConsumer, IdentityNotificationsConsumer>();

        return services;
    }
}
