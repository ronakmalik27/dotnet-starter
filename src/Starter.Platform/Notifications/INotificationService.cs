using Starter.Platform.Paging;
using Starter.SharedKernel;

namespace Starter.Platform.Notifications;

/// <summary>
/// The in-app inbox read/mark-read surface the API calls
/// (in-app-notifications.md section 4). Every method operates on the ACTIVE
/// tenant on the REQUEST path under row-level security, and every one is
/// additionally filtered to the caller's own rows
/// (<c>recipient_user_id = caller</c>): RLS is the tenant boundary underneath, the
/// recipient predicate is the per-user boundary on top. A Platform service (the
/// inbox lives in Platform next to the outbox it projects from), request-scoped
/// like every other RLS-bound read.
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// The caller's notifications, newest first, keyset-paginated
    /// (<c>(created_at desc, id desc)</c>). <paramref name="unreadOnly"/> filters to
    /// unread rows. A malformed cursor is a Validation failure (mapped to 422),
    /// never a throw.
    /// </summary>
    Task<Result<CursorPage<NotificationListItem>>> ListAsync(
        Guid callerUserId,
        bool unreadOnly,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken);

    /// <summary>The caller's unread total (for a badge). Backed by the partial unread index.</summary>
    Task<int> UnreadCountAsync(Guid callerUserId, CancellationToken cancellationToken);

    /// <summary>
    /// Marks one of the caller's notifications read (sets <c>read_at</c> if null;
    /// idempotent). A NotFound failure when the id is not the caller's own
    /// notification - RLS plus the recipient filter make another user's or another
    /// tenant's id invisible, so it reads as not-found (404), never forbidden.
    /// </summary>
    Task<Result> MarkReadAsync(Guid callerUserId, Guid notificationId, CancellationToken cancellationToken);

    /// <summary>Marks all the caller's unread rows read in one statement; returns the count marked.</summary>
    Task<int> MarkAllReadAsync(Guid callerUserId, CancellationToken cancellationToken);
}

/// <summary>
/// A single inbox item (in-app-notifications.md section 4). <c>Data</c> is the
/// stored render jsonb verbatim (a string); the endpoint emits it as raw JSON.
/// </summary>
public sealed record NotificationListItem(
    Guid Id,
    string Type,
    string Data,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ReadAt);
