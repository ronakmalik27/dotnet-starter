using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Starter.Platform.Notifications;

/// <summary>
/// The notifications bootstrap: binds <see cref="EmailOptions"/> and picks
/// the transport from Email:Provider. The console sender is the default
/// (and what an unset provider resolves to); smtp selects the MailKit
/// transport. Senders are stateless, so they register as singletons.
/// </summary>
public static class NotificationsRegistration
{
    public static IServiceCollection AddStarterEmail(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(EmailOptions.SectionName);
        // Validated options: bind, check the data annotations (plus the nested
        // SMTP annotations via EmailOptions.Validate), and fail fast at startup
        // rather than per-request. The defaults all pass, so a zero-config host
        // still boots on the console transport.
        services.AddOptions<EmailOptions>()
            .Bind(section)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var provider = section.GetValue(nameof(EmailOptions.Provider), EmailProvider.Console);
        if (provider == EmailProvider.Smtp)
        {
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
        }
        else
        {
            services.AddSingleton<IEmailSender, ConsoleEmailSender>();
        }

        return services;
    }
}
