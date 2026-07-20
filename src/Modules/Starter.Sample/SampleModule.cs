using Microsoft.Extensions.DependencyInjection;
using Starter.Sample.CreateNote;
using Starter.Sample.DeleteNote;
using Starter.Sample.GetNote;
using Starter.Platform.Data;

namespace Starter.Sample;

/// <summary>
/// The Sample module's bootstrap surface: the single public entry the
/// composition root calls. It contributes the module's DbContext and
/// schema descriptor through the shared module-bootstrap path and
/// registers the use-case slices behind ISampleApi. This is the worked
/// example - copy the shape for a new module.
/// </summary>
public static class SampleModule
{
    /// <summary>
    /// Registers the module against <paramref name="connectionString"/>
    /// (the composition root owns where it comes from). The OutboxWriter the
    /// create handler depends on is registered by the platform's outbox
    /// wiring in the same host.
    /// </summary>
    public static IServiceCollection AddSampleModule(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddModuleDbContext<SampleDbContext>(SampleDbContext.SchemaName, connectionString);

        services.AddScoped<CreateNoteHandler>();
        services.AddScoped<GetNoteHandler>();
        services.AddScoped<DeleteNoteHandler>();
        services.AddScoped<ISampleApi, SampleApi>();

        return services;
    }
}
