using Microsoft.EntityFrameworkCore;
using Starter.Platform.Data;

namespace Starter.Identity;

/// <summary>Design-time factory for dotnet-ef (migrations add/script).</summary>
internal sealed class IdentityDbContextFactory : ModuleDbContextFactory<IdentityDbContext>
{
    protected override string Schema => IdentityDbContext.SchemaName;

    protected override IdentityDbContext Create(DbContextOptions<IdentityDbContext> options) => new(options);
}
