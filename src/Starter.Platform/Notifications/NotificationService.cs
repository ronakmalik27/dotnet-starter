using Microsoft.EntityFrameworkCore;
using Starter.Platform.Data;
using Starter.Platform.Paging;
using Starter.SharedKernel;

namespace Starter.Platform.Notifications;

/// <summary>
/// The in-app inbox read/mark-read surface (in-app-notifications.md section 4),
/// all operating on the ACTIVE tenant on the REQUEST path under row-level security
/// - never the bypass path. Reads run in an explicit transaction so the tenant
/// interceptor sets the RLS GUC (a read with no tenant is fail-closed: zero rows).
/// Every query additionally narrows to <c>recipient_user_id = caller</c>, so a
/// caller only ever sees or flips their own rows; another user's or another
/// tenant's id is invisible (RLS scopes the tenant, the recipient predicate scopes
/// the user), which is why marking a foreign id reads as not-found, never forbidden.
/// </summary>
internal sealed class NotificationService(PlatformDbContext db, Clock clock) : INotificationService
{
    private static readonly Error NotFoundError = new(
        ErrorKind.NotFound, "notifications.not_found", "No such notification.");

    private static readonly Error CursorMalformed = new(
        ErrorKind.Validation, "notifications.cursor_malformed", "The pagination cursor is malformed.");

    public async Task<Result<CursorPage<NotificationListItem>>> ListAsync(
        Guid callerUserId,
        bool unreadOnly,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        KeysetCursor? before = null;
        if (!string.IsNullOrEmpty(cursor))
        {
            if (!KeysetCursor.TryDecode(cursor, out var decoded))
            {
                return CursorMalformed;
            }

            before = decoded;
        }

        var limitPlusOne = PageLimit.Clamp(limit) + 1;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var query = db.Notifications.AsNoTracking().Where(row => row.RecipientUserId == callerUserId);
        if (unreadOnly)
        {
            query = query.Where(row => row.ReadAt == null);
        }

        if (before is { } key)
        {
            // A strictly-earlier position under (created_at desc, id desc): an
            // earlier instant, or the same instant with a smaller id. Server-side,
            // so it uses the same ordering as the ORDER BY - no page skips.
            query = query.Where(row =>
                row.CreatedAt < key.CreatedAt
                || (row.CreatedAt == key.CreatedAt && row.Id.CompareTo(key.Id) < 0));
        }

        var rows = await query
            .OrderByDescending(row => row.CreatedAt)
            .ThenByDescending(row => row.Id)
            .Take(limitPlusOne)
            .Select(row => new NotificationListItem(
                row.Id, row.Type, row.Data, row.CreatedAt, row.ReadAt))
            .ToListAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        var pageSize = limitPlusOne - 1;
        string? nextCursor = null;
        if (rows.Count > pageSize)
        {
            var lastKept = rows[pageSize - 1];
            nextCursor = new KeysetCursor(lastKept.CreatedAt, lastKept.Id).Encode();
            rows.RemoveAt(rows.Count - 1);
        }

        return new CursorPage<NotificationListItem>(rows, nextCursor);
    }

    public async Task<int> UnreadCountAsync(Guid callerUserId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Backed by the partial unread index (tenant_id, recipient_user_id) where
        // read_at is null, so the count never walks the caller's whole history.
        var count = await db.Notifications
            .AsNoTracking()
            .Where(row => row.RecipientUserId == callerUserId && row.ReadAt == null)
            .CountAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return count;
    }

    public async Task<Result> MarkReadAsync(
        Guid callerUserId, Guid notificationId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The recipient predicate is the per-user guard (a caller can only ever
        // flip their own rows); RLS is the tenant boundary underneath. A foreign
        // (other-user or other-tenant) id matches no row here, so the update
        // affects nothing and reads as not-found - never forbidden. Setting
        // read_at to COALESCE(read_at, now) is idempotent: a second mark of an
        // already-read row still matches the row (affected = 1) but never shifts
        // the timestamp.
        var affected = await db.Notifications
            .Where(row => row.Id == notificationId && row.RecipientUserId == callerUserId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(row => row.ReadAt, row => row.ReadAt ?? now),
                cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return affected == 0 ? Result.Failure(NotFoundError) : Result.Success();
    }

    public async Task<int> MarkAllReadAsync(Guid callerUserId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Only the caller's own unread rows; the partial unread index serves the
        // predicate. RLS scopes the update to the active tenant underneath.
        var marked = await db.Notifications
            .Where(row => row.RecipientUserId == callerUserId && row.ReadAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(row => row.ReadAt, now),
                cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return marked;
    }
}
