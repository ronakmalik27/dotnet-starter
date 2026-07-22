using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Events;

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

        // The tenant-admin audit read (RLS-bound, request-scoped) and the
        // super-admin audit read (bypass, cross-tenant).
        services.AddScoped<IAuditQuery, AuditQuery>();
        services.AddScoped<IAuditAdminQuery, AuditAdminQuery>();

        return services;
    }
}
