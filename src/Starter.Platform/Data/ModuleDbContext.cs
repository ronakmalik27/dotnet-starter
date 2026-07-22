using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// Base for every per-module DbContext: one context per
/// module schema. Each
/// context sees only its own schema: cross-schema references are plain ids,
/// never navigations.
/// <para>
/// It also carries the tenant seam. The injected <see cref="ITenantContext"/>
/// is read by the transaction-start interceptor (to set the RLS GUC) and by
/// tenant-stamped writes; <see cref="ApplyTenantFilter{TEntity}"/> applies the
/// EF global query filter against the same instance member, so the singleton-
/// cached compiled model never bakes in one request's tenant.
/// </para>
/// </summary>
public abstract class ModuleDbContext : DbContext
{
    protected ModuleDbContext(DbContextOptions options, string schema, ITenantContext tenantContext)
        : base(options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);
        ArgumentNullException.ThrowIfNull(tenantContext);
        Schema = schema;
        TenantContext = tenantContext;
    }

    /// <summary>The Postgres schema this context owns.</summary>
    public string Schema { get; }

    /// <summary>
    /// The active tenant for this context's unit of work. The platform's
    /// interceptor and outbox writer read it, and the query filter (via
    /// <see cref="ApplyTenantFilter{TEntity}"/>) references it as an instance
    /// member so EF parameterizes it per query. Protected-internal so a module
    /// context whose primary key IS the tenant discriminator (the tenants table)
    /// can write its own filter keyed on the id column; the setters still live
    /// only on the platform's concrete <c>TenantContext</c>, so a subclass can
    /// read the active tenant but never widen it.
    /// </summary>
    protected internal ITenantContext TenantContext { get; }

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

    /// <summary>
    /// Applies the tenant query filter to an <see cref="ITenantOwned"/> entity:
    /// rows are visible only for the active tenant. The filter reads the
    /// DbContext's <see cref="TenantContext"/> instance member (not a captured
    /// constant), so the same compiled model serves every request and EF reads
    /// the current tenant at query time. An unresolved tenant compares against
    /// the empty id and matches zero rows (fail-closed); RLS is the authority
    /// regardless.
    /// </summary>
    protected void ApplyTenantFilter<TEntity>(EntityTypeBuilder<TEntity> entity)
        where TEntity : class, ITenantOwned
    {
        ArgumentNullException.ThrowIfNull(entity);
        entity.HasQueryFilter(row => row.TenantId == TenantContext.TenantId);
    }
}
