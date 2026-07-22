using Microsoft.EntityFrameworkCore;
using Starter.SharedKernel;

namespace Starter.Sample.GetNote;

/// <summary>
/// Reads a note by id. The read runs inside an explicit transaction so the
/// tenant interceptor sets the RLS GUC and the query is bound to the active
/// tenant (a read with no tenant is fail-closed: zero rows, never a leak). An
/// unknown - or cross-tenant - id is a NotFound failure, which the platform
/// maps to 404 (never 403 for a missing row; cross-tenant reads answer 404 so
/// they do not confirm the row exists). The owner id rides the result so the
/// endpoint can authorize the read as the inner owner check.
/// </summary>
internal sealed class GetNoteHandler(SampleDbContext db)
{
    public async Task<Result<(Guid Id, Guid OwnerUserId, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        HandleAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var note = await db.Notes
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        if (note is null)
        {
            return new Error(ErrorKind.NotFound, "sample.note_not_found", "No note exists with that id.");
        }

        return (note.Id, note.OwnerUserId, note.Title, note.Body, note.CreatedAt, note.UpdatedAt);
    }
}
