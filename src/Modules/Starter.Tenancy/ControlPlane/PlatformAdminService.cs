using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Data;
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
    IUserDirectory users,
    Clock clock,
    IOptions<PlatformAdminOptions> options)
{
    private const int MaxTenantPage = 200;
    private const int DefaultTenantPage = 50;

    private static readonly Error TenantNotFound = new(
        ErrorKind.NotFound, "platform.tenant_not_found", "No such tenant.");

    private static readonly Error TargetUserNotFound = new(
        ErrorKind.NotFound, "platform.user_not_found", "No such active user.");

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

    public Task<Result> ReactivateTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken) =>
        ChangeTenantStatusAsync(
            actorUserId,
            tenantId,
            requiredFrom: TenantStatus.Suspended,
            toStatus: TenantStatus.Active,
            wrongState: new Error(
                ErrorKind.Conflict, "platform.tenant_state", "Only a suspended tenant can be reactivated."),
            eventFactory: TenancyEvents.TenantReactivated,
            cancellationToken);

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
        // increment-3 soft-deleted event.
        tenant.Status = TenantStatus.Deleted;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantSoftDeleted(tenantId, actorUserId, now), cancellationToken);
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
        // duplicate event. Only a genuine new grant emits the audit event.
        if (inserted == 1)
        {
            await outbox.EnqueueAsync(
                db, PlatformAdminEvents.PlatformAdminGranted(userId, actorUserId, now), cancellationToken);
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

        await outbox.EnqueueAsync(
            db, PlatformAdminEvents.PlatformAdminRevoked(targetUserId, actorUserId, now), cancellationToken);
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
}
