using Microsoft.EntityFrameworkCore;
using Starter.Sample.Domain;
using Starter.Platform.Data;

namespace Starter.Sample;

/// <summary>
/// The Sample module's context: owns the sample schema and nothing else.
/// The schema binding, the app-side UUIDv7 key
/// convention, and snake_case naming come from ModuleDbContext /
/// StarterDbContextOptions, so a module context stays this small. Exactly
/// one ModuleDbContext per module assembly, named &lt;Module&gt;DbContext
/// and internal - the architecture tests pin all three.
/// </summary>
internal sealed class SampleDbContext(DbContextOptions<SampleDbContext> options)
    : ModuleDbContext(options, SchemaName)
{
    internal const string SchemaName = "sample";

    public DbSet<Note> Notes => Set<Note>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Note>(note =>
        {
            note.Property(n => n.Title).HasMaxLength(200);
            note.Property(n => n.Body).HasColumnType("text");
            // Owners list their own notes newest-first, keyset-paginated on
            // (created_at desc, id desc). The composite index matches that
            // access path exactly - the owner equality prefix plus the sort
            // key - so a page is a single index range scan, no sort, no offset
            // skip. It supersedes the plain owner index (owner_user_id is its
            // leading column, so owner-equality lookups still hit it).
            note.HasIndex(n => new { n.OwnerUserId, n.CreatedAt, n.Id })
                .IsDescending(false, true, true);
        });
    }
}
