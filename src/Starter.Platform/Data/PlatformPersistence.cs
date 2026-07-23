using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Dsar;
using Starter.Platform.Events;
using Starter.Platform.Notifications;

namespace Starter.Platform.Data;

/// <summary>
/// Registers the platform schema's own persistence (outbox, idempotency,
/// domain events) through the same descriptor path the modules
/// use, so readiness and the migration walk see every schema one way. It also
/// registers the audit log (audit-log.md section 9), which lives in Platform next
/// to the outbox it projects from: the Fast-lane projection consumer, the
/// synchronous platform-audit writer, and the two read services.
/// </summary>
public static class PlatformPersistence
{
    public static IServiceCollection AddPlatformPersistence(
        this IServiceCollection services,
        string connectionString)
    {
        services.AddModuleDbContext<PlatformDbContext>(PlatformDbContext.SchemaName, connectionString);

        // The tenant-scoped audit projection (Fast lane). Singleton and
        // singleton-safe: it resolves the scoped PlatformDbContext from the
        // dispatcher's per-consume scope, exactly like NoteIndexConsumer.
        services.AddSingleton<IDomainEventConsumer, AuditProjectionConsumer>();

        // The synchronous platform-audit writer (used by the Tenancy control
        // plane on the bypass path). Stateless apart from the clock, so singleton.
        services.AddSingleton<IPlatformAuditWriter, PlatformAuditWriter>();

        // The in-app notifications projection (in-app-notifications.md sections 3, 5),
        // Fast lane like the audit projection: a curated subset of tenant events
        // becomes per-recipient inbox rows. Singleton and singleton-safe: it
        // resolves the scoped PlatformDbContext from the dispatcher's per-consume
        // scope, exactly like AuditProjectionConsumer.
        services.AddSingleton<IDomainEventConsumer, NotificationProjectionConsumer>();

        // The in-app inbox read/mark-read surface the API calls
        // (in-app-notifications.md section 4): RLS-bound reads and updates of the
        // caller's own rows through the request-scoped PlatformDbContext, never the
        // bypass data source. Request-scoped like the context it reads.
        services.AddScoped<INotificationService, NotificationService>();

        // The install-wide policy-defaults reader (role-templates-and-policy-defaults.md
        // section 3): a no-RLS read of the platform.policy_defaults singleton through
        // the request-role data source, behind a short in-process TTL cache, failing
        // closed to the built-in constants. A SINGLETON, not request-scoped: the login
        // hot path reads it under concurrent brute-force traffic, so the cache is
        // shared process-wide (per-request caching would not help), and the super-admin
        // write path invalidates it. Reads the normal request data source, never bypass.
        services.AddSingleton<Auth.IPolicyDefaults, PolicyDefaultsReader>();

        // The entitlement source (billing-and-entitlements.md section 3): resolves
        // a plan key to its entitlements by reading the no-RLS platform.plans
        // catalogue through the request-scoped PlatformDbContext. Request-scoped
        // like the context it reads, and never touches the bypass data source.
        services.AddScoped<Auth.IEntitlementSource, EntitlementSource>();

        // The feature-flag evaluator (feature-flags.md section 3): resolves a flag
        // against the no-RLS platform.feature_flags catalogue and the RLS-scoped
        // platform.feature_flag_overrides through the request-scoped
        // PlatformDbContext, fail-closed, with a per-request cache. Request-scoped
        // like the context it reads (the cache is per request), and never touches the
        // bypass data source.
        services.AddScoped<Auth.IFeatureFlagEvaluator, FeatureFlagEvaluator>();

        // The tenant feature-flag override control plane (feature-flags.md section
        // 5): RLS-bound set/clear of the tenant's own overrides, gated at the endpoint
        // by feature-flags:manage. Request-scoped like the webhook admin service.
        services.AddScoped<IFeatureFlagAdmin, FeatureFlagAdminService>();

        // The metered-quota counter service (quotas.md section 4): the atomic
        // reserve on the RLS-scoped platform.usage_counters through the request-scoped
        // PlatformDbContext, fail-open (an absent limit is a no-op). Request-scoped
        // like the context it reads, and never touches the bypass data source.
        services.AddScoped<IQuotaService, QuotaService>();

        // The tenant-admin audit read (RLS-bound, request-scoped) and the
        // super-admin audit read (bypass, cross-tenant).
        services.AddScoped<IAuditQuery, AuditQuery>();
        services.AddScoped<IAuditAdminQuery, AuditAdminQuery>();

        // Data export and erasure (data-export-and-erasure.md, GDPR/DSAR). The export
        // service aggregates every module's IDataExportContributor on the request path
        // under RLS (scoped, like the context they read); the erasure service executes
        // the declared deletes on the caller's open bypass transaction (a singleton, the
        // same shape as the platform audit writer). Platform's own contributors: the
        // tenant-owned platform tables it exports, and the declaration of every platform
        // table (plus the event spine) it erases.
        services.AddScoped<ITenantExportService, TenantExportService>();
        services.AddSingleton<ITenantErasureService, TenantErasureService>();
        services.AddScoped<IDataExportContributor, PlatformExportContributors.AuditLog>();
        services.AddScoped<IDataExportContributor, PlatformExportContributors.WebhookEndpoints>();
        services.AddScoped<IDataExportContributor, PlatformExportContributors.WebhookDeliveries>();
        services.AddScoped<IDataExportContributor, PlatformExportContributors.UsageCounters>();
        services.AddScoped<IDataExportContributor, PlatformExportContributors.FeatureFlagOverrides>();
        services.AddSingleton<ITenantErasureContributor, PlatformErasureContributor>();

        return services;
    }
}
