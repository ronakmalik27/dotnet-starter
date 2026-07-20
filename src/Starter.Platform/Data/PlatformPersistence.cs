using Microsoft.Extensions.DependencyInjection;

namespace Starter.Platform.Data;

/// <summary>
/// Registers the platform schema's own persistence (outbox, idempotency,
/// domain events) through the same descriptor path the modules
/// use, so readiness and the migration walk see every schema one way.
/// </summary>
public static class PlatformPersistence
{
    public static IServiceCollection AddPlatformPersistence(
        this IServiceCollection services,
        string connectionString) =>
        services.AddModuleDbContext<PlatformDbContext>(PlatformDbContext.SchemaName, connectionString);
}
