using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Starter.Platform.Events;
using Starter.Platform.Http;

namespace Starter.Platform.Data;

/// <summary>
/// The platform schema's context: outbox, domain_events,
/// and idempotency_keys - the plumbing every module shares. It also owns the
/// DataProtection key ring (see <see cref="DataProtectionKeys"/>), so key
/// material persists to Postgres instead of the container filesystem.
/// </summary>
internal sealed class PlatformDbContext(DbContextOptions<PlatformDbContext> options)
    : ModuleDbContext(options, SchemaName), IDataProtectionKeyContext
{
    internal const string SchemaName = "platform";

    /// <summary>
    /// The DataProtection key ring, persisted to platform.data_protection_keys.
    /// Nothing in the template uses DataProtection today (Google OIDC here is a
    /// custom client-driven code exchange, and the refresh cookie holds an
    /// opaque server-validated token - neither uses DP). This is the correct
    /// scale-out default set ahead of the first DP-dependent feature (cookie
    /// auth, antiforgery, OIDC middleware): keys then survive restarts and are
    /// shared across replicas instead of silently regenerating per instance.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

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
            // The two-lane dispatcher poll index.
            entity.HasIndex(e => new { e.Lane, e.NextAttemptAt })
                .HasFilter("delivered_at is null and poisoned_at is null");
            entity.Property(e => e.EnqueuedAt).HasDefaultValueSql("now()");
            entity.Property(e => e.Attempts).HasDefaultValue(0);
            entity.Property(e => e.NextAttemptAt).HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<IdempotencyKeyRow>(entity =>
        {
            // DDL: pk (user_id, key), response stored as
            // jsonb, created_at drives the 14-day purge.
            entity.ToTable("idempotency_keys");
            entity.HasKey(e => new { e.UserId, e.Key });
            entity.Property(e => e.ResponseBody).HasColumnType("jsonb");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<ProcessedEventRow>(entity =>
        {
            // The reusable dedup ledger: pk (consumer, event_id) is the
            // dedup key ProcessedEventStore claims against; processed_at is
            // a default-now audit stamp. Insert-only.
            entity.ToTable("processed_events");
            entity.HasKey(e => new { e.Consumer, e.EventId });
            entity.Property(e => e.Consumer).HasColumnType("text");
            entity.Property(e => e.ProcessedAt).HasDefaultValueSql("now()");
        });
    }
}
