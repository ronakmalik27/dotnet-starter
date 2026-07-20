using Microsoft.EntityFrameworkCore;
using Starter.Platform.Events;
using Starter.Platform.Http;

namespace Starter.Platform.Data;

/// <summary>
/// The platform schema's context (doc 07 section 3): outbox, domain_events,
/// and idempotency_keys - the plumbing every module shares.
/// </summary>
internal sealed class PlatformDbContext(DbContextOptions<PlatformDbContext> options)
    : ModuleDbContext(options, SchemaName)
{
    internal const string SchemaName = "platform";

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<DomainEventRecord>(entity =>
        {
            // The partitioned parent (monthly by occurred_at, kept forever)
            // is hand-written SQL in the Outbox migration: EF cannot express
            // PARTITION BY, so the table is excluded from generated DDL and
            // this mapping is query/insert-only.
            entity.ToTable("domain_events", table => table.ExcludeFromMigrations());
            entity.HasKey(e => new { e.Id, e.OccurredAt });
            entity.Property(e => e.Payload).HasColumnType("jsonb");
        });

        modelBuilder.Entity<OutboxRow>(entity =>
        {
            entity.ToTable(
                "outbox",
                table => table.HasCheckConstraint("ck_outbox_lane", "lane in ('fast','slow')"));
            entity.HasKey(e => new { e.EventId, e.Lane });
            entity.Property(e => e.Lane)
                .HasConversion(
                    lane => LaneNames.Of(lane),
                    name => name == LaneNames.Fast ? Lane.Fast : Lane.Slow)
                .HasColumnType("text");
            // Doc 07 section 12: the two-lane dispatcher poll index.
            entity.HasIndex(e => new { e.Lane, e.NextAttemptAt })
                .HasFilter("delivered_at is null and poisoned_at is null");
            entity.Property(e => e.EnqueuedAt).HasDefaultValueSql("now()");
            entity.Property(e => e.Attempts).HasDefaultValue(0);
            entity.Property(e => e.NextAttemptAt).HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<IdempotencyKeyRow>(entity =>
        {
            // Doc 07 section 3 DDL: pk (user_id, key), response stored as
            // jsonb, created_at drives the 14-day purge (section 13).
            entity.ToTable("idempotency_keys");
            entity.HasKey(e => new { e.UserId, e.Key });
            entity.Property(e => e.ResponseBody).HasColumnType("jsonb");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("now()");
        });
    }
}
