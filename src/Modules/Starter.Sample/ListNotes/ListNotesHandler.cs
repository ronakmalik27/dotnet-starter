using Microsoft.EntityFrameworkCore;
using Starter.Platform.Paging;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Sample.ListNotes;

/// <summary>
/// Lists an owner's notes newest-first, keyset-paginated on the sort key
/// (CreatedAt desc, Id desc). The worked example of the cursor-pagination
/// convention: filter by owner, apply the keyset predicate for the cursor
/// position, order by the sort key, and take limit+1 to learn whether a
/// further page exists (the extra row is trimmed and its predecessor's sort
/// key becomes the next cursor). The read runs in an explicit transaction so
/// the tenant interceptor sets the RLS GUC (a read with no tenant is
/// fail-closed: zero rows). Owner scoping is layered on top of the tenant
/// boundary, so the list is intrinsically the caller's own notes within the
/// active tenant.
/// <para>
/// It is also the worked example of a WORKSPACE-scoped list (multi-tenancy.md
/// section 12): when the request is on a workspace route (RequireWorkspace bound
/// the workspace context), the list is filtered to that workspace's notes, so
/// workspace A never shows workspace B's notes. A tenant-level list (no workspace
/// bound) is unfiltered by workspace, so it spans every workspace the owner has
/// notes in - the tenant admin's across-workspaces view. The tenant boundary
/// (RLS) sits underneath both, so another tenant's notes are invisible regardless.
/// </para>
/// </summary>
internal sealed class ListNotesHandler(SampleDbContext db, IWorkspaceContext workspace)
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

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var query = db.Notes
            .AsNoTracking()
            .Where(note => note.OwnerUserId == ownerUserId);

        // Workspace filter (multi-tenancy.md section 12): a workspace-scoped list
        // shows only that workspace's notes; a tenant-level list is unfiltered by
        // workspace (spans all of them). RLS still bounds every row to the tenant.
        if (workspace.WorkspaceId is Guid workspaceId)
        {
            query = query.Where(note => note.WorkspaceId == workspaceId);
        }

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

        await transaction.CommitAsync(cancellationToken);

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
