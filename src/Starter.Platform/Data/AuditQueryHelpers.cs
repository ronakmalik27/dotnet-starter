using Starter.Platform.Paging;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// Shared query building for the tenant and super-admin audit reads: cursor
/// parsing and the tenant-log filter chain (actor / action / entity / time
/// range / keyset position), so the RLS-bound read (<see cref="AuditQuery"/>) and
/// the bypass read (<see cref="AuditAdminQuery"/>) apply the identical predicate.
/// </summary>
internal static class AuditQueryHelpers
{
    /// <summary>A malformed keyset cursor: a client error (422), never a throw.</summary>
    public static readonly Error CursorMalformed = new(
        ErrorKind.Validation, "audit.cursor_malformed", "The pagination cursor is malformed.");

    /// <summary>
    /// Parses the optional keyset cursor. Null/empty is "no cursor" (true, null);
    /// a non-decodable value is a failure (false).
    /// </summary>
    public static bool TryParseCursor(string? before, out KeysetCursor? cursor)
    {
        cursor = null;
        if (string.IsNullOrEmpty(before))
        {
            return true;
        }

        if (!KeysetCursor.TryDecode(before, out var decoded))
        {
            return false;
        }

        cursor = decoded;
        return true;
    }

    /// <summary>The shared filter chain over the tenant audit log.</summary>
    public static IQueryable<AuditLogRow> ApplyFilters(
        IQueryable<AuditLogRow> query, AuditQueryFilter filter, KeysetCursor? before)
    {
        if (filter.Actor is Guid actor)
        {
            query = query.Where(row => row.ActorUserId == actor);
        }

        if (filter.Entity is Guid entity)
        {
            query = query.Where(row => row.EntityId == entity);
        }

        if (filter.From is DateTimeOffset from)
        {
            query = query.Where(row => row.OccurredAt >= from);
        }

        if (filter.To is DateTimeOffset to)
        {
            query = query.Where(row => row.OccurredAt < to);
        }

        query = ApplyActionFilter(query, filter.Action);

        if (before is { } key)
        {
            // A strictly-earlier position under (occurred_at desc, id desc): an
            // earlier instant, or the same instant with a smaller id. Server-side,
            // so it uses the same ordering as the ORDER BY - no page skips.
            query = query.Where(row =>
                row.OccurredAt < key.CreatedAt
                || (row.OccurredAt == key.CreatedAt && row.Id.CompareTo(key.Id) < 0));
        }

        return query;
    }

    /// <summary>The action filter over the platform audit log (no entity there).</summary>
    public static IQueryable<PlatformAuditLogRow> ApplyPlatformFilters(
        IQueryable<PlatformAuditLogRow> query, AuditQueryFilter filter, KeysetCursor? before)
    {
        if (filter.Actor is Guid actor)
        {
            query = query.Where(row => row.ActorUserId == actor);
        }

        if (filter.From is DateTimeOffset from)
        {
            query = query.Where(row => row.OccurredAt >= from);
        }

        if (filter.To is DateTimeOffset to)
        {
            query = query.Where(row => row.OccurredAt < to);
        }

        if (!string.IsNullOrWhiteSpace(filter.Action))
        {
            var action = filter.Action.Trim();
            query = action.EndsWith('.')
                ? query.Where(row => row.Action.StartsWith(action))
                : query.Where(row => row.Action == action);
        }

        if (before is { } key)
        {
            query = query.Where(row =>
                row.OccurredAt < key.CreatedAt
                || (row.OccurredAt == key.CreatedAt && row.Id.CompareTo(key.Id) < 0));
        }

        return query;
    }

    /// <summary>
    /// The page window: newest first (occurred_at desc, id desc), take limit+1 to
    /// learn whether a further page exists. Returns the clamped page size.
    /// </summary>
    public static int PageSize(AuditQueryFilter filter) => PageLimit.Clamp(filter.Limit);

    /// <summary>The next-page cursor from the last kept row's sort key.</summary>
    public static string NextCursor(DateTimeOffset occurredAt, Guid id) =>
        new KeysetCursor(occurredAt, id).Encode();

    private static IQueryable<AuditLogRow> ApplyActionFilter(IQueryable<AuditLogRow> query, string? action)
    {
        if (string.IsNullOrWhiteSpace(action))
        {
            return query;
        }

        var trimmed = action.Trim();
        return trimmed.EndsWith('.')
            ? query.Where(row => row.Action.StartsWith(trimmed))
            : query.Where(row => row.Action == trimmed);
    }
}
