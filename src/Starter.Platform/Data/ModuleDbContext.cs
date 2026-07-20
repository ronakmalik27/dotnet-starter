using Microsoft.EntityFrameworkCore;

namespace Starter.Platform.Data;

/// <summary>
/// Base for every per-module DbContext: one context per
/// module schema. Each
/// context sees only its own schema: cross-schema references are plain ids,
/// never navigations.
/// </summary>
public abstract class ModuleDbContext : DbContext
{
    protected ModuleDbContext(DbContextOptions options, string schema)
        : base(options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);
        Schema = schema;
    }

    /// <summary>The Postgres schema this context owns.</summary>
    public string Schema { get; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // Ids are UUIDv7 minted app-side by the SharedKernel Ids helper
        // (PG 17 has no native uuidv7(); clients need
        // pre-generatable ids for idempotency and offline drafts).
        configurationBuilder.Conventions.Add(_ => new AppSideKeyConvention());
    }
}
