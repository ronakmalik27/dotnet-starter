using Microsoft.Extensions.DependencyInjection;
using Starter.Sample.CreateNote;
using Starter.Sample.DeleteNote;
using Starter.Sample.Dsar;
using Starter.Sample.GetNote;
using Starter.Sample.ListNotes;
using Starter.Sample.NoteIndexing;
using Starter.Platform.Data;
using Starter.Platform.Dsar;
using Starter.Platform.Events;

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
        services.AddScoped<ListNotesHandler>();
        services.AddScoped<ISampleApi, SampleApi>();

        // The tenant-scoped read-model consumer (fast lane). Singleton and
        // singleton-safe: it resolves the scoped context from the dispatcher's
        // per-consume scope. Only registered with persistence, like the module.
        services.AddSingleton<IDomainEventConsumer, NoteIndexConsumer>();

        // DSAR (data-export-and-erasure.md): the module contributes its notes to the
        // export (request-path, RLS-bound, scoped like the context it reads) and
        // DECLARES its tenant-owned tables for erasure (a stateless declaration, so
        // singleton). Declaration only - the module touches no bypass.
        services.AddScoped<IDataExportContributor, SampleExportContributor>();
        services.AddSingleton<ITenantErasureContributor, SampleErasureContributor>();

        return services;
    }
}
