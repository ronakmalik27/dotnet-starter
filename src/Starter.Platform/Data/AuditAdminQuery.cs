using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The super-admin audit read (audit-log.md section 6): reads on the BYPASS path,
/// so it crosses tenants (the compliance view). This is a Platform reader type,
/// which Platform may legitimately use - the bypass-containment rule bans modules
/// and the API layer, not Platform, which owns the mechanism. It opens its own
/// <see cref="PlatformDbContext"/> on the bypass connection under the no-tenant
/// context, and strips the EF tenant filter (<c>IgnoreQueryFilters</c>) so the
/// tenant projection is visible across every tenant; RLS is off for the bypass
/// role, so the read spans all tenants.
/// </summary>
internal sealed class AuditAdminQuery(BypassDataSource bypass) : IAuditAdminQuery
{
    public async Task<Result<AuditPage<AuditEntry>>> QueryTenantAsync(
        Guid? tenantFilter, AuditQueryFilter filter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);

        if (!AuditQueryHelpers.TryParseCursor(filter.Before, out var before))
        {
            return AuditQueryHelpers.CursorMalformed;
        }

        var limit = AuditQueryHelpers.PageSize(filter);

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection);

        // IgnoreQueryFilters is the deliberate cross-tenant read: without it the
        // audit-log filter (tenant_id == current tenant) would return nothing
        // under the no-tenant context. RLS is off on the bypass role, so this sees
        // all tenants; a tenant filter narrows it to one.
        IQueryable<AuditLogRow> query = db.AuditLog.IgnoreQueryFilters().AsNoTracking();
        if (tenantFilter is Guid tenant)
        {
            query = query.Where(row => row.TenantId == tenant);
        }

        query = AuditQueryHelpers.ApplyFilters(query, filter, before);
        var rows = await query
            .OrderByDescending(row => row.OccurredAt)
            .ThenByDescending(row => row.Id)
            .Take(limit + 1)
            .Select(row => new AuditEntry(
                row.Id,
                row.TenantId,
                row.OccurredAt,
                row.RecordedAt,
                row.Action,
                row.ActorUserId,
                row.EntityId,
                row.Summary,
                row.Data))
            .ToListAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = AuditQueryHelpers.NextCursor(lastKept.OccurredAt, lastKept.Id);
            rows.RemoveAt(rows.Count - 1);
        }

        return new AuditPage<AuditEntry>(rows, nextCursor);
    }

    public async Task<Result<AuditPage<PlatformAuditEntry>>> QueryPlatformAsync(
        AuditQueryFilter filter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);

        if (!AuditQueryHelpers.TryParseCursor(filter.Before, out var before))
        {
            return AuditQueryHelpers.CursorMalformed;
        }

        var limit = AuditQueryHelpers.PageSize(filter);

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var db = OpenContext(connection);

        // The platform audit log is not tenant-owned (no query filter), so there
        // is nothing to ignore; it is read only here, behind RequirePlatformAdmin.
        var query = AuditQueryHelpers.ApplyPlatformFilters(db.PlatformAuditLog.AsNoTracking(), filter, before);
        var rows = await query
            .OrderByDescending(row => row.OccurredAt)
            .ThenByDescending(row => row.Id)
            .Take(limit + 1)
            .Select(row => new PlatformAuditEntry(
                row.Id,
                row.OccurredAt,
                row.RecordedAt,
                row.Action,
                row.ActorUserId,
                row.SubjectUserId,
                row.Summary,
                row.Data))
            .ToListAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = AuditQueryHelpers.NextCursor(lastKept.OccurredAt, lastKept.Id);
            rows.RemoveAt(rows.Count - 1);
        }

        return new AuditPage<PlatformAuditEntry>(rows, nextCursor);
    }

    private static PlatformDbContext OpenContext(NpgsqlConnection connection) =>
        new(StarterDbContextOptions.ForConnection<PlatformDbContext>(connection).Options, ITenantContext.None);
}
