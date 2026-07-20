using Microsoft.EntityFrameworkCore;
using Starter.Platform.Paging;
using Starter.SharedKernel;

namespace Starter.Sample.ListNotes;

/// <summary>
/// Lists an owner's notes newest-first, keyset-paginated on the sort key
/// (CreatedAt desc, Id desc). The worked example of the cursor-pagination
/// convention: filter by owner, apply the keyset predicate for the cursor
/// position, order by the sort key, and take limit+1 to learn whether a
/// further page exists (the extra row is trimmed and its predecessor's sort
/// key becomes the next cursor). A read has no transaction and no outbox.
/// </summary>
internal sealed class ListNotesHandler(SampleDbContext db)
{
    public async Task<Result<(IReadOnlyList<(Guid Id, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)> Items, string? NextCursor)>>
        HandleAsync(Guid ownerUserId, int limit, string? cursor, CancellationToken cancellationToken)
    {
        // Defensive re-clamp: the endpoint clamps too, but the module owns its
        // own bounds so a direct caller cannot request an unbounded page.
        limit = PageLimit.Clamp(limit);

        KeysetCursor? after = null;
        if (!string.IsNullOrEmpty(cursor))
        {
            if (!KeysetCursor.TryDecode(cursor, out var decoded))
            {
                return new Error(
                    ErrorKind.Validation, "sample.cursor_malformed", "The pagination cursor is malformed.");
            }

            after = decoded;
        }

        var query = db.Notes
            .AsNoTracking()
            .Where(note => note.OwnerUserId == ownerUserId);

        if (after is { } key)
        {
            // Keyset predicate for a strictly-earlier position under
            // (CreatedAt desc, Id desc): an earlier instant, or the same
            // instant with a smaller id. Both comparisons run server-side, so
            // they use the same ordering as the ORDER BY below - no page skips
            // or repeats even when two rows share a CreatedAt.
            query = query.Where(note =>
                note.CreatedAt < key.CreatedAt
                || (note.CreatedAt == key.CreatedAt && note.Id.CompareTo(key.Id) < 0));
        }

        var rows = await query
            .OrderByDescending(note => note.CreatedAt)
            .ThenByDescending(note => note.Id)
            .Take(limit + 1)
            .Select(note => new
            {
                note.Id,
                note.Title,
                note.Body,
                note.CreatedAt,
                note.UpdatedAt,
            })
            .ToListAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            // The limit+1'th row proves a further page exists; the last row we
            // keep supplies the next cursor. Trim the probe row.
            var lastKept = rows[limit - 1];
            nextCursor = new KeysetCursor(lastKept.CreatedAt, lastKept.Id).Encode();
            rows.RemoveAt(rows.Count - 1);
        }

        var items = rows
            .Select(row => (row.Id, row.Title, row.Body, row.CreatedAt, row.UpdatedAt))
            .ToList();

        return (items, nextCursor);
    }
}
