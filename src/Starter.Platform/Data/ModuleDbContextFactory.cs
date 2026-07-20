using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Starter.Platform.Data;

/// <summary>
/// Design-time factory base for dotnet-ef commands (migrations add/script).
/// Reads STARTER_DB_CONNECTION when set (CI, non-default local setups) and
/// falls back to the compose stack's local connection string - synthetic
/// local credentials, not a secret (compose.yaml states the same).
/// </summary>
public abstract class ModuleDbContextFactory<TContext> : IDesignTimeDbContextFactory<TContext>
    where TContext : DbContext
{
    private const string LocalConnectionString =
        "Host=localhost;Port=5432;Database=starter;Username=starter;Password=starter";

    protected abstract string Schema { get; }

    protected abstract TContext Create(DbContextOptions<TContext> options);

    public TContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("STARTER_DB_CONNECTION") ?? LocalConnectionString;

        var options = StarterDbContextOptions
            .ForSchema<TContext>(connectionString, Schema)
            .Options;

        return Create(options);
    }
}
