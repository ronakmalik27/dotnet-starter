using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's context: owns the tenancy schema and nothing else. Both
/// entities are tenant-owned, so each carries the tenant query filter on top of
/// the RLS policy in the database.
/// <para>
/// Memberships filter the ordinary way (a tenant_id column, via
/// ApplyTenantFilter, exactly as Sample does). Tenants are the special case: the
/// tenant's OWN id is the discriminator (no tenant_id column), so the filter
/// keys on id - the RLS policy on tenants keys on id too. The filter reads
/// TenantContext as an instance member, so the singleton-cached compiled model
/// never bakes in one request's tenant.
/// </para>
/// </summary>
internal sealed class TenancyDbContext(DbContextOptions<TenancyDbContext> options, ITenantContext tenantContext)
    : ModuleDbContext(options, SchemaName, tenantContext)
{
    internal const string SchemaName = "tenancy";

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<Membership> Memberships => Set<Membership>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // citext: case-insensitive slug uniqueness in the column type itself,
        // so "Acme" and "acme" collide and no lookup can forget to normalize.
        modelBuilder.HasPostgresExtension("citext");

        modelBuilder.Entity<Tenant>(tenant =>
        {
            tenant.Property(t => t.Slug).HasColumnType("citext");
            tenant.HasIndex(t => t.Slug).IsUnique();
            tenant.Property(t => t.Status).HasMaxLength(32);
            tenant.Property(t => t.Plan).HasColumnType("text");
            // TenantId is a computed alias for the primary key, not a stored
            // column; ignore it and filter on id directly (the tenant's own id
            // is the discriminator, matching the RLS policy keyed on id).
            tenant.Ignore(t => t.TenantId);
            tenant.HasQueryFilter(t => t.Id == TenantContext.TenantId);
        });

        modelBuilder.Entity<Membership>(membership =>
        {
            membership.Property(m => m.Role).HasMaxLength(32);
            membership.Property(m => m.Status).HasMaxLength(32);
            // A user belongs to a tenant at most once; also the mint-check
            // lookup index (tenant_id, user_id).
            membership.HasIndex(m => new { m.TenantId, m.UserId }).IsUnique();
            ApplyTenantFilter(membership);
        });
    }
}
