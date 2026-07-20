using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Starter.Platform.Data;

/// <summary>
/// The registration half of the ADR-0011 bootstrap contract: a module's
/// public Add&lt;Module&gt;Module extension calls this once with its
/// internal context type. The context stays internal while the host, the
/// readiness probe, and the integration fixture consume it through DI and
/// the <see cref="ModuleSchema"/> descriptor.
/// </summary>
public static class ModuleRegistration
{
    public static IServiceCollection AddModuleDbContext<TContext>(
        this IServiceCollection services,
        string schema,
        string connectionString)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddSingleton(StarterDbContextOptions.ForSchema<TContext>(connectionString, schema).Options);
        services.AddScoped<TContext>();
        services.AddSingleton(new ModuleSchema(schema, typeof(TContext)));
        return services;
    }
}
