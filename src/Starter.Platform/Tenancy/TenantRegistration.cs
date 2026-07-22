using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Http;

namespace Starter.Platform.Tenancy;

/// <summary>
/// DI and endpoint wiring for tenant context: the scoped
/// <see cref="ITenantContext"/> and the per-endpoint tenant requirement.
/// </summary>
public static class TenantRegistration
{
    /// <summary>
    /// Registers the request/consumer-scoped tenant context. The concrete
    /// <see cref="TenantContext"/> and the <see cref="ITenantContext"/> view of
    /// it resolve to the same scoped instance, so the middleware (or dispatcher)
    /// sets it and every DbContext in the scope reads it.
    /// </summary>
    public static IServiceCollection AddStarterTenantContext(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<TenantContext>();
        services.AddScoped<ITenantContext>(provider => provider.GetRequiredService<TenantContext>());

        // The request-scoped workspace context (multi-tenancy.md section 12): the
        // concrete WorkspaceContext and its IWorkspaceContext view resolve to the
        // same scoped instance, so the RequireWorkspace gate binds it and every
        // tenant-owned write in the scope reads it. Unresolved by default, so a
        // tenant-level request stamps a null workspace_id.
        services.AddScoped<WorkspaceContext>();
        services.AddScoped<IWorkspaceContext>(provider => provider.GetRequiredService<WorkspaceContext>());

        var resolution = services.AddOptions<TenantResolutionOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configuration is not null)
        {
            resolution.Bind(configuration.GetSection(TenantResolutionOptions.SectionName));
        }

        return services;
    }
}

/// <summary>Endpoint opt-in for the tenant requirement.</summary>
public static class TenantEndpointExtensions
{
    /// <summary>
    /// Marks an endpoint tenant-scoped: a request that reaches it with no
    /// resolved tenant gets 400 <c>starter:tenant-required</c>. Order it before
    /// idempotency/authorization is unnecessary; it only reads the resolved
    /// context the middleware already set, so its position among the other
    /// filters does not matter.
    /// </summary>
    public static TBuilder RequireTenant<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddEndpointFilter(static async (context, next) =>
        {
            var tenant = context.HttpContext.RequestServices.GetRequiredService<ITenantContext>();
            if (!tenant.IsResolved)
            {
                return TypedResults.Problem(StarterProblems.TenantRequired(context.HttpContext));
            }

            return await next(context);
        });
    }
}
