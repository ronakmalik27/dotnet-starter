using Microsoft.EntityFrameworkCore;

namespace Starter.Platform.Data;

/// <summary>
/// Base for every per-module DbContext (doc 13 section 3: one context per
/// module schema; doc 07 section 2 owns the module-to-schema map). Each
/// context sees only its own schema: cross-schema references are plain ids,
/// never navigations (HLD 3.2, doc 07 section 1).
/// </summary>
public abstract class ModuleDbContext : DbContext
{
    protected ModuleDbContext(DbContextOptions options, string schema)
        : base(options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);
        Schema = schema;
    }

    /// <summary>The Postgres schema this context owns (doc 07 section 2).</summary>
    public string Schema { get; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // Ids are UUIDv7 minted app-side by the SharedKernel Ids helper
        // (doc 07 section 1: PG 17 has no native uuidv7(); clients need
        // pre-generatable ids for idempotency and offline drafts).
        configurationBuilder.Conventions.Add(_ => new AppSideKeyConvention());
    }
}
