using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Starter.Platform.Events;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Registers the outbound-webhooks feature (webhooks.md section 10): the validated
/// options, the SSRF DNS resolver, the DataProtection secret wrapper, the SSRF-guarded
/// named HttpClient, the Fast-lane fan-out consumer, the leader-elected delivery worker,
/// the retention maintenance pass, and the RLS-bound admin service. Everything lives in
/// Platform next to the outbox and audit log, so no bypass-allowlist change is needed and
/// the whole feature is deletable by dropping this registration and the two tables.
/// </summary>
public static class WebhookRegistration
{
    public static IServiceCollection AddWebhooks(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Validated options: the numeric-range annotations plus the duration validator are
        // checked at startup, so a bad Webhooks override fails the boot, not the worker.
        services.AddOptions<WebhookOptions>()
            .Bind(configuration.GetSection(WebhookOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<WebhookOptions>, WebhookOptionsValidator>();

        // The SSRF DNS resolver (a seam the test suite substitutes) and the DataProtection
        // signing-secret wrapper.
        services.AddSingleton<IWebhookDnsResolver, SystemWebhookDnsResolver>();
        services.AddSingleton<WebhookSecretProtector>();

        // The SSRF-guarded delivery client: resolve-once-connect-to-validated-ip, redirects
        // off, and per-request URL redaction on its OTel spans.
        services.AddHttpClient(WebhookHttpClient.ClientName)
            .ConfigurePrimaryHttpMessageHandler(WebhookHttpClient.CreatePrimaryHandler)
            .AddHttpMessageHandler(() => new WebhookTraceMarkerHandler());

        // The Fast-lane fan-out consumer (singleton and singleton-safe: it resolves the
        // scoped PlatformDbContext per consume, exactly like the audit projection).
        services.AddSingleton<IDomainEventConsumer, WebhookFanoutConsumer>();

        // The leader-elected delivery worker and the retention maintenance pass.
        services.AddHostedService<WebhookDeliveryWorker>();
        services.AddSingleton<WebhookMaintenance>();

        // The RLS-bound admin control plane the Api endpoints call.
        services.AddScoped<IWebhookAdmin, WebhookAdminService>();

        return services;
    }
}
