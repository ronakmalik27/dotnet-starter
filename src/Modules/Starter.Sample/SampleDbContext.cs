using Microsoft.EntityFrameworkCore;
using Starter.Sample.Domain;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Sample;

/// <summary>
/// The Sample module's context: owns the sample schema and nothing else.
/// The schema binding, the app-side UUIDv7 key
/// convention, and snake_case naming come from ModuleDbContext /
/// StarterDbContextOptions, so a module context stays this small. Exactly
/// one ModuleDbContext per module assembly, named &lt;Module&gt;DbContext
/// and internal - the architecture tests pin all three.
/// <para>
/// Both entities are tenant-owned, so each gets the tenant query filter
/// (ApplyTenantFilter, reading the injected tenant context) on top of the RLS
/// policy in the database. This is the copy-me shape for a tenant-aware module.
/// </para>
/// </summary>
internal sealed class SampleDbContext(DbContextOptions<SampleDbContext> options, ITenantContext tenantContext)
    : ModuleDbContext(options, SchemaName, tenantContext)
{
    internal const string SchemaName = "sample";

    public DbSet<Note> Notes => Set<Note>();

    public DbSet<NoteIndex> NoteIndex => Set<NoteIndex>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Note>(note =>
        {
            note.Property(n => n.Title).HasMaxLength(200);
            note.Property(n => n.Body).HasColumnType("text");
            // Owners list their own notes newest-first, keyset-paginated on
            // (created_at desc, id desc), and every query is now tenant-scoped
            // too. The composite index leads with tenant_id (the RLS/filter
            // equality prefix), then the owner equality, then the sort key, so
            // a page is a single index range scan within one tenant.
            note.HasIndex(n => new { n.TenantId, n.OwnerUserId, n.CreatedAt, n.Id })
                .IsDescending(false, false, true, true);
            ApplyTenantFilter(note);
        });

        modelBuilder.Entity<NoteIndex>(index =>
        {
            index.HasKey(i => i.NoteId);
            ApplyTenantFilter(index);
        });
    }
}
