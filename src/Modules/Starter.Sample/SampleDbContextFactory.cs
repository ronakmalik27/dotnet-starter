using Microsoft.EntityFrameworkCore;
using Starter.Platform.Data;

namespace Starter.Sample;

/// <summary>Design-time factory for dotnet-ef (migrations add/script).</summary>
internal sealed class SampleDbContextFactory : ModuleDbContextFactory<SampleDbContext>
{
    protected override string Schema => SampleDbContext.SchemaName;

    protected override SampleDbContext Create(DbContextOptions<SampleDbContext> options) => new(options);
}
