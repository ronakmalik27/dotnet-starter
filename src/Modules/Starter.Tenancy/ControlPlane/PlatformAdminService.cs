using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Dsar;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The platform super-admin plane (multi-tenancy.md section 7): cross-tenant
/// tenant lifecycle, platform-admin roster management, and audited impersonation,
/// all on the bypass data source. This is explicitly cross-tenant control-plane
/// work - listing every tenant, administering the platform-admin table, and
/// writing the impersonation audit spine - so it is one of the bypass-containment
/// allowlisted types.
/// <para>
/// Every write that carries a domain event opens a transaction on a TenancyDbContext
/// enlisted on the bypass connection, does its raw-SQL platform-table work (or its
/// EF tenant-table write) on that same connection and transaction, and enqueues the
/// event through the OutboxWriter, so the state change and its audit event commit
/// together. Tenant-lifecycle events bind the context to the target tenant (so the
/// event carries tenant_id = the target); platform-admin events run under the
/// no-tenant context (tenant_id null); impersonation events bind the target tenant.
/// </para>
/// </summary>
internal sealed class PlatformAdminService(
    BypassDataSource bypass,
    OutboxWriter outbox,
    IPlatformAuditWriter auditWriter,
    IUserDirectory users,
    Clock clock,
    IOptions<PlatformAdminOptions> options,
    ITenantErasureService erasure,
    IOptions<DsarOptions> dsarOptions)
{
    private const int MaxTenantPage = 200;
    private const int DefaultTenantPage = 50;

    private static readonly Error TenantNotFound = new(
        ErrorKind.NotFound, "platform.tenant_not_found", "No such tenant.");

    private static readonly Error TargetUserNotFound = new(
        ErrorKind.NotFound, "platform.user_not_found", "No such active user.");

    private static readonly Error PlanNotFound = new(
        ErrorKind.NotFound, "platform.plan_not_found", "No such plan.");

    private static readonly Error FeatureFlagNotFound = new(
        ErrorKind.NotFound, "platform.feature_flag_not_found", "No such feature flag.");

    // --- Tenants (cross-tenant reads on the bypass path) ------------------

    public async Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)>>
        ListTenantsAsync(string? query, int limit, CancellationToken cancellationToken)
    {
        var take = Math.Clamp(limit <= 0 ? DefaultTenantPage : limit, 1, MaxTenantPage);

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.None);

        // IgnoreQueryFilters is the deliberate cross-tenant read: without it the
        // tenants filter (id == current tenant) would return nothing under the
        // no-tenant context. RLS is off on the bypass role, so this sees all.
        IQueryable<Tenant> tenants = db.Tenants.IgnoreQueryFilters().AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query))
        {
            // Escape LIKE wildcards so a caller-supplied query is a literal
            // substring match, not a pattern (the default backslash escape).
            var escaped = query.Trim()
                .Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("%", "\\%", StringComparison.Ordinal)
                .Replace("_", "\\_", StringComparison.Ordinal);
            var pattern = $"%{escaped}%";
            tenants = tenants.Where(t =>
                EF.Functions.ILike(t.Slug, pattern) || EF.Functions.ILike(t.Name, pattern));
        }

        var rows = await tenants
            .OrderBy(t => t.CreatedAt)
            .ThenBy(t => t.Id)
            .Take(take)
            .Select(t => new
            {
                t.Id,
                t.Slug,
                t.Name,
                t.Status,
                t.Plan,
                t.SeatLimit,
                t.CreatedAt,
            })
            .ToListAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.Slug, row.Name, row.Status, row.Plan, row.SeatLimit, row.CreatedAt))
            .ToList();
    }

    public async Task<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)?>
        GetTenantAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.None);

        var row = await db.Tenants
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(t => t.Id == tenantId)
            .Select(t => new
            {
                t.Id,
                t.Slug,
                t.Name,
                t.Status,
                t.Plan,
                t.SeatLimit,
                t.CreatedAt,
            })
            .SingleOrDefaultAsync(cancellationToken);

        return row is null
            ? null
            : (row.Id, row.Slug, row.Name, row.Status, row.Plan, row.SeatLimit, row.CreatedAt);
    }

    // --- Tenant lifecycle (bypass-path writes, one transaction each) ------

    public Task<Result> SuspendTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken) =>
        ChangeTenantStatusAsync(
            actorUserId,
            tenantId,
            requiredFrom: TenantStatus.Active,
            toStatus: TenantStatus.Suspended,
            wrongState: new Error(
                ErrorKind.Conflict, "platform.tenant_state", "Only an active tenant can be suspended."),
            eventFactory: TenancyEvents.TenantSuspended,
            cancellationToken);

    public async Task<Result> ReactivateTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken)
    {
        // WIDENED for DSAR (data-export-and-erasure.md section 2): a soft-deleted
        // tenant must be recoverable within the retention window, so both
        // `suspended -> active` and `deleted -> active` reactivate, and the
        // deleted_at stamp is cleared on the transition (the standard "restore within
        // N days" model). A HARD-deleted tenant cannot be reactivated - its rows are
        // gone. Not routed through ChangeTenantStatusAsync because that helper allows
        // exactly one source state and does not clear deleted_at.
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenant = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenant is null)
        {
            return Result.Failure(TenantNotFound);
        }

        if (tenant.Status is not (TenantStatus.Suspended or TenantStatus.Deleted))
        {
            return Result.Failure(new Error(
                ErrorKind.Conflict,
                "platform.tenant_state",
                "Only a suspended or deleted tenant can be reactivated."));
        }

        tenant.Status = TenantStatus.Active;
        tenant.DeletedAt = null;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(db, TenancyEvents.TenantReactivated(tenantId, actorUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> DeleteTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenant = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenant is null)
        {
            return Result.Failure(TenantNotFound);
        }

        if (tenant.Status == TenantStatus.Deleted)
        {
            return Result.Failure(new Error(
                ErrorKind.Conflict, "platform.tenant_state", "The tenant is already deleted."));
        }

        // Soft-delete via status, never a hard row delete (audit). Reuses the
        // increment-3 soft-deleted event. Stamp deleted_at: the DSAR retention window
        // is measured from it, and reactivate clears it (data-export-and-erasure.md
        // section 2).
        tenant.Status = TenantStatus.Deleted;
        tenant.DeletedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantSoftDeleted(tenantId, actorUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    /// <summary>
    /// Hard-deletes (erases) a tenant (data-export-and-erasure.md section 5, GDPR Art.
    /// 17): the single most dangerous operation in the starter, so ALL of it runs in
    /// ONE bypass transaction, committed once, and every erasure statement carries an
    /// explicit tenant filter. Loads the tenant <c>FOR UPDATE</c> (the row lock closes
    /// the reactivate/erase race now that <c>deleted -> active</c> exists); requires
    /// <c>status = deleted</c> (else a tenant-state Conflict) and either the retention
    /// window elapsed or <paramref name="force"/> (else a retention Conflict); captures
    /// the redacted pre-purge snapshot; erases every declared table plus the session
    /// revoke; records <c>platform.tenant.erased</c> on the surviving platform audit
    /// log; then commits. A missing (or already-erased) tenant is a NotFound.
    /// </summary>
    public async Task<Result<TenantErasureSnapshot>> EraseTenantAsync(
        Guid actorUserId, Guid tenantId, bool force, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction;

        // 1. Lock the tenant row. The lock is essential: a concurrent reactivate
        // could otherwise flip the tenant back to active between this check and the
        // delete, erasing a just-restored tenant.
        var target = await ReadTenantForErasureAsync(connection, dbTransaction, tenantId, cancellationToken);
        if (target is null)
        {
            return Result.Failure<TenantErasureSnapshot>(TenantNotFound);
        }

        var (status, deletedAt) = target.Value;
        if (status != TenantStatus.Deleted)
        {
            return Result.Failure<TenantErasureSnapshot>(new Error(
                ErrorKind.Conflict,
                "platform.tenant_state",
                "The tenant must be soft-deleted before it can be erased."));
        }

        var retention = TimeSpan.FromDays(dsarOptions.Value.RetentionDays);
        var elapsesAt = (deletedAt ?? now) + retention;
        if (!force && (deletedAt is null || elapsesAt > now))
        {
            return Result.Failure<TenantErasureSnapshot>(new Error(
                ErrorKind.Conflict,
                "platform.retention_not_elapsed",
                $"The retention window has not elapsed; it elapses at {elapsesAt:O}. Pass force to erase now."));
        }

        // 2. Capture the operator's pre-purge compliance snapshot (secrets redacted).
        var snapshot = await erasure.CaptureSnapshotAsync(connection, dbTransaction, tenantId, cancellationToken);

        // 3. Erase every declared table plus the session revoke.
        await erasure.EraseAsync(connection, dbTransaction, tenantId, cancellationToken);

        // 4. Record the erasure on the platform audit log (NOT tenant-scoped: the
        // tenant's own spine is being destroyed). Then commit - so an erased tenant
        // can never exist without its audit record.
        await auditWriter.WriteAsync(
            connection,
            dbTransaction,
            PlatformAdminEvents.TenantErased(tenantId, actorUserId, now),
            subjectUserId: null,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(snapshot);
    }

    // --- Plans (operator catalogue on platform.plans, bypass-path) --------
    // The plan catalogue is a no-RLS platform table (billing-and-entitlements.md
    // section 2). CRUD is raw SQL on the bypass connection (the platform_admins
    // shape), so the nullable features/permissions arrays are written as SQL NULL
    // (unrestricted), never as {} (which would strip everything). A create/update
    // is audited SYNCHRONOUSLY through the platform audit writer in the same
    // transaction as the catalogue write, exactly like a super-admin grant.

    public async Task<IReadOnlyList<(string Key, string Name, IReadOnlyList<string>? Features, IReadOnlyList<string>? Permissions, IReadOnlyDictionary<string, int> Limits, bool IsDefault, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListPlansAsync(CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select key, name, features, permissions, limits, is_default, created_at, updated_at "
            + "from platform.plans order by created_at, key",
            connection);

        var plans =
            new List<(string, string, IReadOnlyList<string>?, IReadOnlyList<string>?, IReadOnlyDictionary<string, int>, bool, DateTimeOffset, DateTimeOffset)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var features = await reader.IsDBNullAsync(2, cancellationToken)
                ? null
                : (IReadOnlyList<string>)reader.GetFieldValue<string[]>(2);
            var permissions = await reader.IsDBNullAsync(3, cancellationToken)
                ? null
                : (IReadOnlyList<string>)reader.GetFieldValue<string[]>(3);
            plans.Add((
                reader.GetString(0),
                reader.GetString(1),
                features,
                permissions,
                ParseLimits(reader.GetFieldValue<string>(4)),
                reader.GetBoolean(5),
                reader.GetFieldValue<DateTimeOffset>(6),
                reader.GetFieldValue<DateTimeOffset>(7)));
        }

        return plans;
    }

    public async Task<Result> CreatePlanAsync(
        Guid actorUserId,
        string key,
        string name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool isDefault,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(name);

        key = key.Trim();
        name = name.Trim();
        if (ValidatePlanShape(key, name, limits) is { } validation)
        {
            return Result.Failure(validation);
        }

        var now = clock.UtcNow;
        var limitsJson = JsonSerializer.Serialize(limits);

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction;

        // A new default demotes the current one first, so the exactly-one-default
        // partial unique index never sees a torn state in a sequential write.
        if (isDefault)
        {
            await DemoteDefaultsAsync(connection, dbTransaction, exceptKey: key, now, cancellationToken);
        }

        try
        {
            await using var insert = new NpgsqlCommand(
                "insert into platform.plans "
                + "(key, name, features, permissions, limits, is_default, created_at, updated_at) "
                + "values (@key, @name, @features, @permissions, @limits, @default, @now, @now)",
                connection,
                dbTransaction);
            insert.Parameters.AddWithValue("key", key);
            insert.Parameters.AddWithValue("name", name);
            AddArrayParameter(insert, "features", features);
            AddArrayParameter(insert, "permissions", permissions);
            insert.Parameters.Add(new NpgsqlParameter("limits", NpgsqlDbType.Jsonb) { Value = limitsJson });
            insert.Parameters.AddWithValue("default", isDefault);
            insert.Parameters.AddWithValue("now", now);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return DefaultOrKeyConflict(exception);
        }

        var created = PlatformAdminEvents.PlanCreated(key, actorUserId, now);
        await auditWriter.WriteAsync(connection, dbTransaction, created, subjectUserId: null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> UpdatePlanAsync(
        Guid actorUserId,
        string key,
        string? name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool? isDefault,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        key = key.Trim();
        name = name?.Trim();

        if (name is { Length: 0 })
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "platform.plan_name_required", "A plan name cannot be empty."));
        }

        if (limits is not null && !HasPositiveSeatLimit(limits))
        {
            return Result.Failure(SeatLimitRequired);
        }

        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction;

        // Lock the row (FOR UPDATE) and rewrite it whole, so a null field means
        // "unchanged" (keep the existing value) rather than "set null". This is the
        // simplest correct handling of the features/permissions tri-state on a
        // PATCH: a provided array replaces, an absent one is preserved.
        var existing = await ReadPlanForUpdateAsync(connection, dbTransaction, key, cancellationToken);
        if (existing is null)
        {
            return Result.Failure(PlanNotFound);
        }

        var newIsDefault = isDefault ?? existing.Value.IsDefault;
        if (newIsDefault)
        {
            await DemoteDefaultsAsync(connection, dbTransaction, exceptKey: key, now, cancellationToken);
        }

        try
        {
            await using var update = new NpgsqlCommand(
                "update platform.plans set "
                + "name = @name, features = @features, permissions = @permissions, "
                + "limits = @limits, is_default = @default, updated_at = @now where key = @key",
                connection,
                dbTransaction);
            update.Parameters.AddWithValue("key", key);
            update.Parameters.AddWithValue("name", name ?? existing.Value.Name);
            AddArrayParameter(update, "features", features ?? existing.Value.Features);
            AddArrayParameter(update, "permissions", permissions ?? existing.Value.Permissions);
            var limitsJson = limits is null ? existing.Value.Limits : JsonSerializer.Serialize(limits);
            update.Parameters.Add(new NpgsqlParameter("limits", NpgsqlDbType.Jsonb) { Value = limitsJson });
            update.Parameters.AddWithValue("default", newIsDefault);
            update.Parameters.AddWithValue("now", now);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return DefaultOrKeyConflict(exception);
        }

        var updated = PlatformAdminEvents.PlanUpdated(key, actorUserId, now);
        await auditWriter.WriteAsync(connection, dbTransaction, updated, subjectUserId: null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> AssignPlanAsync(
        Guid actorUserId, Guid tenantId, string planKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(planKey);
        planKey = planKey.Trim();
        if (planKey.Length == 0)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "platform.plan_required", "A plan key is required."));
        }

        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // The plan must exist (a 404 otherwise), so a tenant is never assigned a
        // dangling plan key. Its seatLimit is denormalized onto the tenant row so
        // the race-proof seat check in invitation-accept stays unchanged.
        var seatLimit = await ReadPlanSeatLimitAsync(connection, planKey, cancellationToken);
        if (seatLimit is null)
        {
            return Result.Failure(PlanNotFound);
        }

        // Bind the context to the target tenant (the ChangeTenantStatusAsync
        // structure): one transaction, the EF write of plan + seat_limit, the
        // plan-changed event enqueue, commit.
        await using var db = OpenContext(connection, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenant = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenant is null)
        {
            return Result.Failure(TenantNotFound);
        }

        var oldPlan = tenant.Plan;
        tenant.Plan = planKey;
        tenant.SeatLimit = seatLimit.Value;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantPlanChanged(tenantId, oldPlan, planKey, actorUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Feature flags (operator catalogue on platform.feature_flags, bypass-path) -
    // The feature-flag catalogue is a no-RLS platform table (feature-flags.md
    // section 2), the plan-CRUD pattern: raw SQL on the bypass connection, audited
    // SYNCHRONOUSLY through the platform audit writer in the same transaction as the
    // catalogue write. Feature flags fail CLOSED, so nothing is seeded (a flag is a
    // deliberate operator act; there is nothing to gate until one is defined).

    public async Task<IReadOnlyList<(string Key, string Description, bool DefaultEnabled, int? RolloutPercentage, bool TenantOverridable, bool Archived, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListFeatureFlagsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select key, description, default_enabled, rollout_percentage, tenant_overridable, "
            + "archived_at, created_at, updated_at from platform.feature_flags order by created_at, key",
            connection);

        var flags =
            new List<(string, string, bool, int?, bool, bool, DateTimeOffset, DateTimeOffset)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var rollout = await reader.IsDBNullAsync(3, cancellationToken)
                ? (int?)null
                : reader.GetInt32(3);
            var archived = !await reader.IsDBNullAsync(5, cancellationToken);
            flags.Add((
                reader.GetString(0),
                reader.GetString(1),
                reader.GetBoolean(2),
                rollout,
                reader.GetBoolean(4),
                archived,
                reader.GetFieldValue<DateTimeOffset>(6),
                reader.GetFieldValue<DateTimeOffset>(7)));
        }

        return flags;
    }

    public async Task<Result> CreateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string description,
        bool defaultEnabled,
        int? rolloutPercentage,
        bool tenantOverridable,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(description);

        key = key.Trim();
        description = description.Trim();
        if (ValidateFeatureFlagShape(key, description, rolloutPercentage) is { } validation)
        {
            return Result.Failure(validation);
        }

        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction;

        try
        {
            await using var insert = new NpgsqlCommand(
                "insert into platform.feature_flags "
                + "(key, description, default_enabled, rollout_percentage, tenant_overridable, "
                + "archived_at, created_at, updated_at) "
                + "values (@key, @description, @default, @rollout, @overridable, null, @now, @now)",
                connection,
                dbTransaction);
            insert.Parameters.AddWithValue("key", key);
            insert.Parameters.AddWithValue("description", description);
            insert.Parameters.AddWithValue("default", defaultEnabled);
            insert.Parameters.Add(new NpgsqlParameter("rollout", NpgsqlDbType.Integer)
            {
                Value = (object?)rolloutPercentage ?? DBNull.Value,
            });
            insert.Parameters.AddWithValue("overridable", tenantOverridable);
            insert.Parameters.AddWithValue("now", now);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return Result.Failure(new Error(
                ErrorKind.Conflict,
                "platform.feature_flag_key_taken",
                "A feature flag with that key already exists."));
        }

        var created = PlatformAdminEvents.FeatureFlagCreated(key, actorUserId, now);
        await auditWriter.WriteAsync(connection, dbTransaction, created, subjectUserId: null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> UpdateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string? description,
        bool? defaultEnabled,
        int? rolloutPercentage,
        bool? tenantOverridable,
        bool? archived,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        key = key.Trim();
        description = description?.Trim();

        if (description is { Length: 0 })
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "platform.feature_flag_description_required", "A description cannot be empty."));
        }

        if (rolloutPercentage is < 0 or > 100)
        {
            return Result.Failure(RolloutOutOfRange);
        }

        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction;

        // Lock the row (FOR UPDATE) and rewrite it whole, so a null argument means
        // "unchanged" rather than "set null" - the PATCH tri-state. rollout stays a
        // set-or-keep facet (clearing a rollout is not offered here). archived is a
        // tri-state too: true archives (archived_at = now), false unarchives (null),
        // null leaves it.
        var existing = await ReadFeatureFlagForUpdateAsync(connection, dbTransaction, key, cancellationToken);
        if (existing is null)
        {
            return Result.Failure(FeatureFlagNotFound);
        }

        var newArchivedAt = archived switch
        {
            true => existing.Value.ArchivedAt ?? now,
            false => (DateTimeOffset?)null,
            null => existing.Value.ArchivedAt,
        };

        await using var update = new NpgsqlCommand(
            "update platform.feature_flags set "
            + "description = @description, default_enabled = @default, rollout_percentage = @rollout, "
            + "tenant_overridable = @overridable, archived_at = @archived, updated_at = @now where key = @key",
            connection,
            dbTransaction);
        update.Parameters.AddWithValue("key", key);
        update.Parameters.AddWithValue("description", description ?? existing.Value.Description);
        update.Parameters.AddWithValue("default", defaultEnabled ?? existing.Value.DefaultEnabled);
        update.Parameters.Add(new NpgsqlParameter("rollout", NpgsqlDbType.Integer)
        {
            Value = (object?)(rolloutPercentage ?? existing.Value.RolloutPercentage) ?? DBNull.Value,
        });
        update.Parameters.AddWithValue("overridable", tenantOverridable ?? existing.Value.TenantOverridable);
        update.Parameters.Add(new NpgsqlParameter("archived", NpgsqlDbType.TimestampTz)
        {
            Value = (object?)newArchivedAt ?? DBNull.Value,
        });
        update.Parameters.AddWithValue("now", now);
        await update.ExecuteNonQueryAsync(cancellationToken);

        var updated = PlatformAdminEvents.FeatureFlagUpdated(key, actorUserId, now);
        await auditWriter.WriteAsync(connection, dbTransaction, updated, subjectUserId: null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Platform admins (bypass-path roster on platform.platform_admins) --

    public async Task<IReadOnlyList<(Guid UserId, Guid? GrantedBy, DateTimeOffset GrantedAt)>>
        ListPlatformAdminsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select user_id, granted_by, granted_at from platform.platform_admins order by granted_at, user_id",
            connection);

        var admins = new List<(Guid, Guid?, DateTimeOffset)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var grantedBy = await reader.IsDBNullAsync(1, cancellationToken)
                ? (Guid?)null
                : reader.GetGuid(1);
            admins.Add((reader.GetGuid(0), grantedBy, reader.GetFieldValue<DateTimeOffset>(2)));
        }

        return admins;
    }

    public async Task<Result> GrantPlatformAdminAsync(
        Guid actorUserId,
        Guid? targetUserId,
        string? email,
        CancellationToken cancellationToken)
    {
        var resolved = await ResolveTargetUserAsync(targetUserId, email, cancellationToken);
        if (resolved.IsFailure)
        {
            return Result.Failure(resolved.Error);
        }

        var userId = resolved.Value;
        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.None);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        await using var insert = new NpgsqlCommand(
            "insert into platform.platform_admins (user_id, granted_by, granted_at) "
            + "values (@user, @by, @at) on conflict (user_id) do nothing",
            connection,
            dbTransaction);
        insert.Parameters.AddWithValue("user", userId);
        insert.Parameters.AddWithValue("by", actorUserId);
        insert.Parameters.AddWithValue("at", now);
        var inserted = await insert.ExecuteNonQueryAsync(cancellationToken);

        // Idempotent: an already-granted user is a benign success with no
        // duplicate event. Only a genuine new grant emits the audit event AND
        // writes the platform audit row - on the SAME branch, in the SAME
        // transaction, PK = the emitted event id (audit-log.md section 2), so
        // there is never an audit row without a real action, and never a
        // duplicate. platform.admin.* is null-tenant, so it is audited here
        // synchronously, not by the async tenant projection.
        if (inserted == 1)
        {
            var granted = PlatformAdminEvents.PlatformAdminGranted(userId, actorUserId, now);
            await outbox.EnqueueAsync(db, granted, cancellationToken);
            await auditWriter.WriteAsync(
                connection, dbTransaction, granted, subjectUserId: userId, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    public async Task<Result> RevokePlatformAdminAsync(
        Guid actorUserId,
        Guid targetUserId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.None);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        // Lock the whole (tiny) admin set so concurrent revokes serialize: the
        // second waits for the first to commit, then sees the reduced count, so
        // the last-admin guard can never be raced into leaving zero admins.
        var admins = await ReadAdminIdsForUpdateAsync(connection, dbTransaction, cancellationToken);
        if (!admins.Contains(targetUserId))
        {
            return Result.Failure(new Error(
                ErrorKind.NotFound, "platform.admin_not_found", "That user is not a platform admin."));
        }

        if (admins.Count <= 1)
        {
            return Result.Failure(new Error(
                ErrorKind.Conflict, "platform.last_admin", "The last platform admin cannot be revoked."));
        }

        await using var delete = new NpgsqlCommand(
            "delete from platform.platform_admins where user_id = @user", connection, dbTransaction);
        delete.Parameters.AddWithValue("user", targetUserId);
        await delete.ExecuteNonQueryAsync(cancellationToken);

        // This branch is the only one that commits the delete + emits the event
        // (the not-found and last-admin guards above returned early, committing
        // nothing), so the platform audit row rides the same transaction with
        // PK = the emitted event id (audit-log.md section 2).
        var revoked = PlatformAdminEvents.PlatformAdminRevoked(targetUserId, actorUserId, now);
        await outbox.EnqueueAsync(db, revoked, cancellationToken);
        await auditWriter.WriteAsync(
            connection, dbTransaction, revoked, subjectUserId: targetUserId, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Impersonation (audited, time-boxed, revocable) -------------------

    public async Task<Result<(Guid GrantId, Guid SubjectUserId, Guid TargetTenantId, DateTimeOffset ExpiresAt)>>
        StartImpersonationAsync(
            Guid actorUserId,
            Guid tenantId,
            Guid? targetUserId,
            string reason,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reason);

        reason = reason.Trim();
        if (reason.Length == 0)
        {
            return Result.Failure<(Guid, Guid, Guid, DateTimeOffset)>(new Error(
                ErrorKind.Validation, "platform.reason_required", "A written reason is required."));
        }

        // A target user, when named, must be a real active account (impersonating
        // a ghost user is refused). The tenant may be suspended (a support case),
        // so only existence is checked, not status.
        if (targetUserId is Guid target && await users.GetEmailAsync(target, cancellationToken) is null)
        {
            return Result.Failure<(Guid, Guid, Guid, DateTimeOffset)>(TargetUserNotFound);
        }

        var now = clock.UtcNow;
        // The grant window: the smaller of the configured window and the
        // 15-minute access cap, so an impersonation token can never outlive the
        // normal access-token lifetime.
        var window = TimeSpan.FromMinutes(options.Value.ImpersonationMinutes);
        var capped = window <= StarterAuth.AccessTokenLifetime ? window : StarterAuth.AccessTokenLifetime;
        var expiresAt = now + capped;
        var grantId = Ids.NewId(now);
        var subjectUserId = targetUserId ?? actorUserId;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // The tenant must exist (any status). Read before the write transaction.
        if (!await TenantExistsAsync(connection, tenantId, cancellationToken))
        {
            return Result.Failure<(Guid, Guid, Guid, DateTimeOffset)>(TenantNotFound);
        }

        await using var db = OpenContext(connection, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        // The grant row and the ImpersonationStarted event share this
        // transaction, so no impersonation token can exist without its audit row.
        await using var insert = new NpgsqlCommand(
            "insert into platform.impersonation_grants "
            + "(id, platform_admin_user_id, target_tenant_id, target_user_id, reason, issued_at, expires_at, ended_at) "
            + "values (@id, @admin, @tenant, @user, @reason, @issued, @expires, null)",
            connection,
            dbTransaction);
        insert.Parameters.AddWithValue("id", grantId);
        insert.Parameters.AddWithValue("admin", actorUserId);
        insert.Parameters.AddWithValue("tenant", tenantId);
        // Explicitly typed so a null target user (impersonating as the admin, not
        // as a specific user) binds as a uuid NULL rather than relying on Npgsql
        // to infer the type of an untyped null.
        insert.Parameters.Add(new NpgsqlParameter("user", NpgsqlDbType.Uuid)
        {
            Value = (object?)targetUserId ?? DBNull.Value,
        });
        insert.Parameters.AddWithValue("reason", reason);
        insert.Parameters.AddWithValue("issued", now);
        insert.Parameters.AddWithValue("expires", expiresAt);
        await insert.ExecuteNonQueryAsync(cancellationToken);

        await outbox.EnqueueAsync(
            db,
            PlatformAdminEvents.ImpersonationStarted(grantId, actorUserId, tenantId, targetUserId, now),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success((grantId, subjectUserId, tenantId, expiresAt));
    }

    public async Task<Result> EndImpersonationAsync(
        Guid actorUserId,
        Guid grantId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // The event must carry the grant's target tenant, so read it first.
        var target = await ReadGrantTargetAsync(connection, grantId, cancellationToken);
        if (target is null)
        {
            return Result.Failure(new Error(
                ErrorKind.NotFound, "platform.grant_not_found", "No such impersonation grant."));
        }

        await using var db = OpenContext(connection, ITenantContext.ForTenant(target.Value.TenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        await using var update = new NpgsqlCommand(
            "update platform.impersonation_grants set ended_at = @now "
            + "where id = @id and ended_at is null",
            connection,
            dbTransaction);
        update.Parameters.AddWithValue("now", now);
        update.Parameters.AddWithValue("id", grantId);
        var ended = await update.ExecuteNonQueryAsync(cancellationToken);

        // Idempotent: a grant already ended is a benign no-op success with no
        // duplicate event. Only a live grant transitions and emits the event.
        if (ended == 1)
        {
            await outbox.EnqueueAsync(
                db, PlatformAdminEvents.ImpersonationEnded(grantId, actorUserId, now), cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    // --- helpers ----------------------------------------------------------

    private async Task<Result> ChangeTenantStatusAsync(
        Guid actorUserId,
        Guid tenantId,
        string requiredFrom,
        string toStatus,
        Error wrongState,
        Func<Guid, Guid, DateTimeOffset, DomainEventRecord> eventFactory,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenant = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenant is null)
        {
            return Result.Failure(TenantNotFound);
        }

        if (tenant.Status != requiredFrom)
        {
            return Result.Failure(wrongState);
        }

        tenant.Status = toStatus;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(db, eventFactory(tenantId, actorUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private async Task<Result<Guid>> ResolveTargetUserAsync(
        Guid? targetUserId, string? email, CancellationToken cancellationToken)
    {
        if (targetUserId is Guid userId)
        {
            // The id must name a real active account.
            if (await users.GetEmailAsync(userId, cancellationToken) is null)
            {
                return Result.Failure<Guid>(TargetUserNotFound);
            }

            return Result.Success(userId);
        }

        if (!string.IsNullOrWhiteSpace(email))
        {
            var found = await users.FindUserIdByEmailAsync(email.Trim(), cancellationToken);
            return found is Guid resolved
                ? Result.Success(resolved)
                : Result.Failure<Guid>(TargetUserNotFound);
        }

        return Result.Failure<Guid>(new Error(
            ErrorKind.Validation, "platform.user_required", "A userId or email is required."));
    }

    private static async Task<HashSet<Guid>> ReadAdminIdsForUpdateAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select user_id from platform.platform_admins for update", connection, transaction);
        var ids = new HashSet<Guid>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }

    private static async Task<bool> TenantExistsAsync(
        NpgsqlConnection connection, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select 1 from tenancy.tenants where id = @id limit 1", connection);
        command.Parameters.AddWithValue("id", tenantId);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    // Reads the tenant's status and deleted_at under a row lock (FOR UPDATE) on the
    // bypass connection, so a concurrent reactivate cannot race the erase between the
    // retention check and the purge. RLS is off on the bypass role, so the explicit
    // `where id` is the tenant filter. Null when the tenant does not exist.
    private static async Task<(string Status, DateTimeOffset? DeletedAt)?> ReadTenantForErasureAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select status, deleted_at from tenancy.tenants where id = @id for update",
            connection,
            transaction);
        command.Parameters.AddWithValue("id", tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var deletedAt = await reader.IsDBNullAsync(1, cancellationToken)
            ? (DateTimeOffset?)null
            : reader.GetFieldValue<DateTimeOffset>(1);
        return (reader.GetString(0), deletedAt);
    }

    private static async Task<(Guid TenantId, DateTimeOffset? EndedAt)?> ReadGrantTargetAsync(
        NpgsqlConnection connection, Guid grantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select target_tenant_id, ended_at from platform.impersonation_grants where id = @id limit 1",
            connection);
        command.Parameters.AddWithValue("id", grantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var endedAt = await reader.IsDBNullAsync(1, cancellationToken)
            ? (DateTimeOffset?)null
            : reader.GetFieldValue<DateTimeOffset>(1);
        return (reader.GetGuid(0), endedAt);
    }

    private static TenancyDbContext OpenContext(NpgsqlConnection connection, ITenantContext tenantContext)
    {
        var options = StarterDbContextOptions.ForConnection<TenancyDbContext>(connection).Options;
        return new TenancyDbContext(options, tenantContext);
    }

    // --- Plan helpers -----------------------------------------------------

    private static readonly Error SeatLimitRequired = new(
        ErrorKind.Validation,
        "platform.plan_seat_limit_required",
        "A plan must declare a positive seatLimit in its limits (tenant.seat_limit is not null).");

    private static Error? ValidatePlanShape(
        string key, string name, IReadOnlyDictionary<string, int>? limits)
    {
        if (key.Length == 0 || key.Length > 64)
        {
            return new Error(
                ErrorKind.Validation, "platform.plan_key_invalid", "A plan key must be 1-64 characters.");
        }

        if (name.Length == 0)
        {
            return new Error(
                ErrorKind.Validation, "platform.plan_name_required", "A plan name is required.");
        }

        // seatLimit is REQUIRED and must be positive: tenant.seat_limit is NOT NULL,
        // so assign-plan can never land a null or zero limit that would silently
        // block every future invitation (billing-and-entitlements.md section 5).
        return HasPositiveSeatLimit(limits) ? null : SeatLimitRequired;
    }

    private static bool HasPositiveSeatLimit(IReadOnlyDictionary<string, int>? limits) =>
        limits is not null && limits.TryGetValue("seatLimit", out var seatLimit) && seatLimit > 0;

    private static void AddArrayParameter(NpgsqlCommand command, string name, IReadOnlyList<string>? values)
    {
        // A null list is SQL NULL (unrestricted); a non-null list is a text[]
        // (closed to exactly that set). Explicitly typed so a null binds as a
        // text[] NULL rather than relying on Npgsql to infer an untyped null.
        command.Parameters.Add(new NpgsqlParameter(name, NpgsqlDbType.Array | NpgsqlDbType.Text)
        {
            Value = values is null ? DBNull.Value : values.ToArray(),
        });
    }

    private static Result DefaultOrKeyConflict(PostgresException exception) =>
        exception.ConstraintName == "ux_plans_is_default"
            ? Result.Failure(new Error(
                ErrorKind.Conflict,
                "platform.plan_default_conflict",
                "Another plan is already the default; retry."))
            : Result.Failure(new Error(
                ErrorKind.Conflict,
                "platform.plan_key_taken",
                "A plan with that key already exists."));

    private static async Task DemoteDefaultsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string exceptKey,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "update platform.plans set is_default = false, updated_at = @now "
            + "where is_default and key <> @key",
            connection,
            transaction);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("key", exceptKey);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<PlanRowValues?> ReadPlanForUpdateAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string key,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select name, features, permissions, limits, is_default from platform.plans "
            + "where key = @key for update",
            connection,
            transaction);
        command.Parameters.AddWithValue("key", key);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var features = await reader.IsDBNullAsync(1, cancellationToken)
            ? null
            : reader.GetFieldValue<string[]>(1);
        var permissions = await reader.IsDBNullAsync(2, cancellationToken)
            ? null
            : reader.GetFieldValue<string[]>(2);
        return new PlanRowValues(
            reader.GetString(0), features, permissions, reader.GetFieldValue<string>(3), reader.GetBoolean(4));
    }

    private static async Task<int?> ReadPlanSeatLimitAsync(
        NpgsqlConnection connection, string planKey, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select limits from platform.plans where key = @key limit 1", connection);
        command.Parameters.AddWithValue("key", planKey);
        var limits = await command.ExecuteScalarAsync(cancellationToken) as string;
        if (limits is null)
        {
            return null;
        }

        var parsed = ParseLimits(limits);
        return parsed.TryGetValue("seatLimit", out var seatLimit) && seatLimit > 0 ? seatLimit : null;
    }

    private static Dictionary<string, int> ParseLimits(string limits)
    {
        if (string.IsNullOrWhiteSpace(limits))
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, int>>(limits)
                ?? new Dictionary<string, int>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }
    }

    private readonly record struct PlanRowValues(
        string Name, string[]? Features, string[]? Permissions, string Limits, bool IsDefault);

    // --- Feature-flag helpers ---------------------------------------------

    private static readonly Error RolloutOutOfRange = new(
        ErrorKind.Validation,
        "platform.feature_flag_rollout_range",
        "A rollout percentage must be between 0 and 100.");

    private static Error? ValidateFeatureFlagShape(string key, string description, int? rolloutPercentage)
    {
        if (key.Length == 0 || key.Length > 64)
        {
            return new Error(
                ErrorKind.Validation, "platform.feature_flag_key_invalid", "A flag key must be 1-64 characters.");
        }

        if (description.Length == 0)
        {
            return new Error(
                ErrorKind.Validation, "platform.feature_flag_description_required", "A description is required.");
        }

        return rolloutPercentage is < 0 or > 100 ? RolloutOutOfRange : null;
    }

    private static async Task<FeatureFlagRowValues?> ReadFeatureFlagForUpdateAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string key,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select description, default_enabled, rollout_percentage, tenant_overridable, archived_at "
            + "from platform.feature_flags where key = @key for update",
            connection,
            transaction);
        command.Parameters.AddWithValue("key", key);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var rollout = await reader.IsDBNullAsync(2, cancellationToken)
            ? (int?)null
            : reader.GetInt32(2);
        var archivedAt = await reader.IsDBNullAsync(4, cancellationToken)
            ? (DateTimeOffset?)null
            : reader.GetFieldValue<DateTimeOffset>(4);
        return new FeatureFlagRowValues(
            reader.GetString(0), reader.GetBoolean(1), rollout, reader.GetBoolean(3), archivedAt);
    }

    private readonly record struct FeatureFlagRowValues(
        string Description, bool DefaultEnabled, int? RolloutPercentage, bool TenantOverridable, DateTimeOffset? ArchivedAt);
}
