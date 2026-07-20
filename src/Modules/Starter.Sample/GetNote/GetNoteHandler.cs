using Microsoft.EntityFrameworkCore;
using Starter.SharedKernel;

namespace Starter.Sample.GetNote;

/// <summary>
/// Reads a note by id. A read has no transaction and no outbox: the query
/// half of the create/get pair. An unknown id is a NotFound failure, which
/// the platform maps to 404 (never 403 for a missing row). The owner id
/// rides the result so the endpoint can authorize the read.
/// </summary>
internal sealed class GetNoteHandler(SampleDbContext db)
{
    public async Task<Result<(Guid Id, Guid OwnerUserId, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        HandleAsync(Guid id, CancellationToken cancellationToken)
    {
        var note = await db.Notes
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == id, cancellationToken);

        if (note is null)
        {
            return new Error(ErrorKind.NotFound, "sample.note_not_found", "No note exists with that id.");
        }

        return (note.Id, note.OwnerUserId, note.Title, note.Body, note.CreatedAt, note.UpdatedAt);
    }
}
