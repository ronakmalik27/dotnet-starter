using Microsoft.EntityFrameworkCore;

namespace Starter.Platform.Data;

/// <summary>Design-time factory for dotnet-ef (migrations add/script).</summary>
internal sealed class PlatformDbContextFactory : ModuleDbContextFactory<PlatformDbContext>
{
    protected override string Schema => PlatformDbContext.SchemaName;

    protected override PlatformDbContext Create(DbContextOptions<PlatformDbContext> options) => new(options);
}
