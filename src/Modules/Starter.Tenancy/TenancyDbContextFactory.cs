using Microsoft.EntityFrameworkCore;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy;

/// <summary>Design-time factory for dotnet-ef (migrations add/script).</summary>
internal sealed class TenancyDbContextFactory : ModuleDbContextFactory<TenancyDbContext>
{
    protected override string Schema => TenancyDbContext.SchemaName;

    protected override TenancyDbContext Create(
        DbContextOptions<TenancyDbContext> options, ITenantContext tenantContext) =>
        new(options, tenantContext);
}
