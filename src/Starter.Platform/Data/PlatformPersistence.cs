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

        // The tenant-admin audit read (RLS-bound, request-scoped) and the
        // super-admin audit read (bypass, cross-tenant).
        services.AddScoped<IAuditQuery, AuditQuery>();
        services.AddScoped<IAuditAdminQuery, AuditAdminQuery>();

        return services;
    }
}
