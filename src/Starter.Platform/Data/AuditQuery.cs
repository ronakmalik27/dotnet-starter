using Microsoft.EntityFrameworkCore;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The tenant-admin audit read (audit-log.md section 6): reads the RLS-bound
/// <see cref="PlatformDbContext"/>, so the read is scoped to the caller's tenant
/// by the same authoritative boundary as every other tenant read. The read runs
/// in an explicit transaction so the tenant interceptor sets the RLS GUC (a read
/// with no tenant is fail-closed: zero rows).
/// </summary>
internal sealed class AuditQuery(PlatformDbContext db) : IAuditQuery
{
    public async Task<Result<AuditPage<AuditEntry>>> QueryAsync(
        AuditQueryFilter filter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);

        if (!AuditQueryHelpers.TryParseCursor(filter.Before, out var before))
        {
            return AuditQueryHelpers.CursorMalformed;
        }

        var limit = AuditQueryHelpers.PageSize(filter);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var query = AuditQueryHelpers.ApplyFilters(db.AuditLog.AsNoTracking(), filter, before);
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

        await transaction.CommitAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = AuditQueryHelpers.NextCursor(lastKept.OccurredAt, lastKept.Id);
            rows.RemoveAt(rows.Count - 1);
        }

        return new AuditPage<AuditEntry>(rows, nextCursor);
    }
}
