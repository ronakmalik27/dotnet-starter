using Microsoft.Extensions.DependencyInjection;
using Starter.Tenancy.ControlPlane;
using Starter.Platform.Data;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's bootstrap surface: the single public entry the
/// composition root calls. It contributes the module's DbContext and schema
/// descriptor through the shared module-bootstrap path and registers the
/// control-plane slices behind ITenancyApi.
/// </summary>
public static class TenancyModule
{
    /// <summary>
    /// Registers the module against <paramref name="connectionString"/> (the
    /// request-role connection, for the scoped context). The self-serve
    /// provisioner and the membership directory additionally inject the platform
    /// <c>BypassDataSource</c> singleton (already registered by the composition
    /// root) for their explicitly cross-tenant work; the OutboxWriter and
    /// ITenancyApi's Identity dependency are resolved from the same host.
    /// </summary>
    public static IServiceCollection AddTenancyModule(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddModuleDbContext<TenancyDbContext>(TenancyDbContext.SchemaName, connectionString);

        services.AddScoped<TenantProvisioner>();
        services.AddScoped<MembershipDirectory>();
        services.AddScoped<ITenancyApi, TenancyApi>();

        return services;
    }
}
