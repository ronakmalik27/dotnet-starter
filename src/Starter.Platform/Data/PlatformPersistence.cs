using Microsoft.Extensions.DependencyInjection;

namespace Starter.Platform.Data;

/// <summary>
/// Registers the platform schema's own persistence (outbox, idempotency,
/// domain events) through the same ADR-0011 descriptor path the modules
/// use, so readiness and the migration walk see all nine schemas one way.
/// </summary>
public static class PlatformPersistence
{
    public static IServiceCollection AddPlatformPersistence(
        this IServiceCollection services,
        string connectionString) =>
        services.AddModuleDbContext<PlatformDbContext>(PlatformDbContext.SchemaName, connectionString);
}
