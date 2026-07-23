using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Starter.Platform.Events;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;
using Starter.Platform.Webhooks;

namespace Starter.Platform.Data;

/// <summary>
/// The platform schema's context: outbox, domain_events,
/// and idempotency_keys - the plumbing every module shares. It also owns the
/// DataProtection key ring (see <see cref="DataProtectionKeys"/>), so key
/// material persists to Postgres instead of the container filesystem.
/// Platform tables are not tenant-owned (no RLS), with deliberate exceptions:
/// <c>platform.audit_log</c> (the per-tenant audit projection, <see cref="AuditLogRow"/>)
/// and the outbound-webhooks tables <c>platform.webhook_endpoints</c>
/// (<see cref="WebhookEndpointRow"/>) and <c>platform.webhook_deliveries</c>
/// (<see cref="WebhookDeliveryRow"/>) are ALL tenant-owned and RLS-enforced, so a tenant
/// admin reading them is bound by the same authoritative boundary as every other tenant
/// read (audit-log.md section 9, webhooks.md section 1). The context carries an
/// <see cref="ITenantContext"/> so it fits the one module-context shape, and the
/// interceptor sets the RLS GUC for those reads/writes.
/// </summary>
internal sealed class PlatformDbContext(DbContextOptions<PlatformDbContext> options, ITenantContext tenantContext)
    : ModuleDbContext(options, SchemaName, tenantContext), IDataProtectionKeyContext
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
            // tenant_id: not-null for tenant-owned work, null for a platform
            // event. Query/insert-only (the raw-SQL partitioned table adds the
            // column), so this is a mapping, not generated DDL.
            entity.Property(e => e.TenantId);
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

        modelBuilder.Entity<PlatformAdminRow>(entity =>
        {
            // The cross-tenant operators. No RLS (a platform table); read and
            // written only on the bypass path. pk is the user id, so a repeat
            // grant is an upsert-friendly conflict on the primary key.
            entity.ToTable("platform_admins");
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.UserId).ValueGeneratedNever();
            entity.Property(e => e.GrantedAt).HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<PlanRow>(entity =>
        {
            // The operator-owned plan catalogue (billing-and-entitlements.md
            // section 2). No RLS (a global platform table, like platform_admins),
            // so NO ApplyTenantFilter: the request path reads it for entitlement
            // resolution, the super-admin path edits it on the bypass source. pk is
            // the plan key (the value stored in tenant.plan). features/permissions
            // are NULLABLE text[] (SQL NULL = unrestricted; a non-null array is
            // closed to exactly that set); limits is jsonb.
            entity.ToTable("plans");
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).ValueGeneratedNever();
            entity.Property(e => e.Name).HasColumnType("text");
            entity.Property(e => e.Features).HasColumnType("text[]");
            entity.Property(e => e.Permissions).HasColumnType("text[]");
            entity.Property(e => e.Limits).HasColumnType("jsonb");
            // Exactly one default plan: a partial unique index on is_default WHERE
            // is_default makes a torn two-default state impossible even under a
            // concurrent double-promote (app discipline alone could not).
            entity.HasIndex(e => e.IsDefault)
                .IsUnique()
                .HasFilter("is_default")
                .HasDatabaseName("ux_plans_is_default");
        });

        modelBuilder.Entity<FeatureFlagRow>(entity =>
        {
            // The operator-owned feature-flag catalogue (feature-flags.md section 2).
            // No RLS (a global platform table, like plans / platform_admins), so NO
            // ApplyTenantFilter: the request path (the evaluator) reads it, the
            // super-admin path edits it on the bypass source. pk is the flag key.
            // default_enabled is the fixed default; rollout_percentage (nullable)
            // overrides it via the deterministic bucket when set; archived_at hides
            // and fail-closes the flag.
            entity.ToTable("feature_flags");
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).ValueGeneratedNever();
            entity.Property(e => e.Description).HasColumnType("text");
        });

        modelBuilder.Entity<FeatureFlagOverrideRow>(entity =>
        {
            // A tenant's own override of a flag (feature-flags.md section 2),
            // tenant-owned and RLS-enforced (the RLS policy is hand-written in the
            // migration). The unique (tenant_id, flag_key, scope_type, scope_id) index
            // uses NULLS NOT DISTINCT - the roles-catalogue idiom, NOT the
            // role_assignments two-partial-index shape - so a tenant-scope override
            // (scope_id NULL) is unique per flag and a PUT-as-upsert works when
            // scope_id is NULL.
            entity.ToTable("feature_flag_overrides");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.FlagKey).HasColumnType("text");
            entity.Property(e => e.ScopeType).HasColumnType("text");
            entity.HasIndex(e => new { e.TenantId, e.FlagKey, e.ScopeType, e.ScopeId })
                .IsUnique()
                .HasDatabaseName("ux_feature_flag_overrides_tenant_flag_scope")
                .HasAnnotation("Npgsql:NullsDistinct", false);
            ApplyTenantFilter(entity);
        });

        modelBuilder.Entity<ImpersonationGrantRow>(entity =>
        {
            // The impersonation audit spine. No RLS; written and read only on
            // the bypass path. The pk covers the per-request re-check; the two
            // listing indexes back "sessions by this admin" and "sessions into
            // this tenant".
            entity.ToTable("impersonation_grants");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Reason).HasColumnType("text");
            entity.HasIndex(e => e.PlatformAdminUserId);
            entity.HasIndex(e => e.TargetTenantId);
        });

        modelBuilder.Entity<AuditLogRow>(entity =>
        {
            // The per-tenant audit projection (audit-log.md section 3). The FIRST
            // and only tenant-owned, RLS-enforced table in the platform schema:
            // the RLS policy is hand-written in the migration (EF cannot express
            // ENABLE/FORCE RLS or a policy), and the EF query filter is applied
            // here for ergonomics + defense in depth, exactly like every other
            // tenant-owned entity. pk = the source event id (idempotent
            // projection); data is the event payload verbatim (jsonb).
            entity.ToTable("audit_log");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Action).HasColumnType("text");
            entity.Property(e => e.Summary).HasColumnType("text");
            entity.Property(e => e.Data).HasColumnType("jsonb");
            // The default reverse-chronological feed and keyset cursor.
            entity.HasIndex(e => new { e.TenantId, e.OccurredAt })
                .IsDescending(false, true)
                .HasDatabaseName("ix_audit_log_tenant_occurred");
            // The two common filters, actor and action, each keyset-ordered.
            entity.HasIndex(e => new { e.TenantId, e.ActorUserId, e.OccurredAt })
                .IsDescending(false, false, true)
                .HasDatabaseName("ix_audit_log_tenant_actor_occurred");
            entity.HasIndex(e => new { e.TenantId, e.Action, e.OccurredAt })
                .IsDescending(false, false, true)
                .HasDatabaseName("ix_audit_log_tenant_action_occurred");
            ApplyTenantFilter(entity);
        });

        modelBuilder.Entity<PlatformAuditLogRow>(entity =>
        {
            // The platform (null-tenant) audit log (audit-log.md section 4). NOT
            // tenant-owned, no RLS, no tenant filter - consistent with every other
            // platform table. Written only on the bypass path (in the same
            // transaction as the admin grant/revoke it records) and read only
            // behind RequirePlatformAdmin. pk = the source event id.
            entity.ToTable("platform_audit_log");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Action).HasColumnType("text");
            entity.Property(e => e.Summary).HasColumnType("text");
            entity.Property(e => e.Data).HasColumnType("jsonb");
        });

        modelBuilder.Entity<WebhookEndpointRow>(entity =>
        {
            // A tenant's registered webhook receiver (webhooks.md section 2), tenant-owned
            // and RLS-enforced (the RLS policy is hand-written in the migration). The
            // signing secret persists ONLY as DataProtection ciphertext plus a display
            // prefix; the raw secret is never a column.
            entity.ToTable("webhook_endpoints");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Url).HasColumnType("text");
            entity.Property(e => e.Description).HasColumnType("text");
            entity.Property(e => e.EventTypes).HasColumnType("text[]");
            entity.Property(e => e.SigningSecretEncrypted).HasColumnType("text");
            entity.Property(e => e.SecretPrefix).HasColumnType("text");
            entity.HasIndex(e => e.TenantId).HasDatabaseName("ix_webhook_endpoints_tenant");
            ApplyTenantFilter(entity);
        });

        modelBuilder.Entity<WebhookDeliveryRow>(entity =>
        {
            // One (event, endpoint) delivery (webhooks.md section 2), tenant-owned and
            // RLS-enforced. The unique (endpoint_id, event_id) is the fan-out idempotency
            // key; the partial (next_attempt_at) where status = 'pending' index serves the
            // worker's claim, mirroring the outbox poll index.
            entity.ToTable("webhook_deliveries");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EventType).HasColumnType("text");
            entity.Property(e => e.Payload).HasColumnType("jsonb");
            entity.Property(e => e.Status).HasColumnType("text");
            entity.Property(e => e.LastError).HasColumnType("text");
            entity.HasIndex(e => new { e.EndpointId, e.EventId })
                .IsUnique()
                .HasDatabaseName("ux_webhook_deliveries_endpoint_event");
            entity.HasIndex(e => e.NextAttemptAt)
                .HasFilter("status = 'pending'")
                .HasDatabaseName("ix_webhook_deliveries_claim");
            entity.HasIndex(e => new { e.TenantId, e.EndpointId, e.CreatedAt })
                .IsDescending(false, false, true)
                .HasDatabaseName("ix_webhook_deliveries_tenant_endpoint_created");
            ApplyTenantFilter(entity);
        });

        modelBuilder.Entity<UsageCounterRow>(entity =>
        {
            // The metered-quota counter (quotas.md section 2), tenant-owned and
            // RLS-enforced (the RLS policy is hand-written in the migration). Unlike
            // plans / feature_flags this is a NORMAL request-role DML table (no REVOKE
            // in TenantRoleProvisioner): a tenant's own request increments its own
            // counter under RLS. The composite pk (tenant_id, metric, period_start) is
            // the upsert conflict target; used is bigint so a high-volume metric cannot
            // overflow.
            entity.ToTable("usage_counters");
            entity.HasKey(e => new { e.TenantId, e.Metric, e.PeriodStart })
                .HasName("pk_usage_counters");
            entity.Property(e => e.Metric).HasColumnType("text");
            entity.Property(e => e.PeriodStart).HasColumnType("date");
            entity.Property(e => e.Used).HasColumnType("bigint");
            ApplyTenantFilter(entity);
        });
    }

    /// <summary>The operator-owned plan catalogue (no RLS; read on the request path, edited on the bypass path).</summary>
    internal DbSet<PlanRow> Plans => Set<PlanRow>();

    /// <summary>The operator-owned feature-flag catalogue (no RLS; read by the evaluator, edited on the bypass path).</summary>
    internal DbSet<FeatureFlagRow> FeatureFlags => Set<FeatureFlagRow>();

    /// <summary>The tenant's feature-flag overrides (RLS-enforced; set/cleared on the request path, read by the evaluator).</summary>
    internal DbSet<FeatureFlagOverrideRow> FeatureFlagOverrides => Set<FeatureFlagOverrideRow>();

    /// <summary>The cross-tenant operators (mapping only; the runtime uses raw bypass SQL).</summary>
    internal DbSet<PlatformAdminRow> PlatformAdmins => Set<PlatformAdminRow>();

    /// <summary>The impersonation audit spine (mapping only; the runtime uses raw bypass SQL).</summary>
    internal DbSet<ImpersonationGrantRow> ImpersonationGrants => Set<ImpersonationGrantRow>();

    /// <summary>The per-tenant audit projection (RLS-enforced; written by the consumer, read RLS-bound or via bypass).</summary>
    internal DbSet<AuditLogRow> AuditLog => Set<AuditLogRow>();

    /// <summary>The platform (null-tenant) audit log (no RLS; written on the bypass path, read behind RequirePlatformAdmin).</summary>
    internal DbSet<PlatformAuditLogRow> PlatformAuditLog => Set<PlatformAuditLogRow>();

    /// <summary>The tenant's webhook endpoints (RLS-enforced; register/list/update/rotate/delete on the request path).</summary>
    internal DbSet<WebhookEndpointRow> WebhookEndpoints => Set<WebhookEndpointRow>();

    /// <summary>The webhook deliveries (RLS-enforced; written by the fan-out consumer, drained by the worker on the bypass path).</summary>
    internal DbSet<WebhookDeliveryRow> WebhookDeliveries => Set<WebhookDeliveryRow>();

    /// <summary>The metered-quota counters (RLS-enforced; incremented on the request path, read for the usage report).</summary>
    internal DbSet<UsageCounterRow> UsageCounters => Set<UsageCounterRow>();
}
