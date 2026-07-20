using Microsoft.EntityFrameworkCore;
using Starter.SharedKernel;

namespace Starter.Sample.DeleteNote;

/// <summary>
/// Deletes a note by id in a transaction. An unknown id is a NotFound
/// failure, which the platform maps to 404. Ownership was already checked by
/// the endpoint (authorize on the read, then delete), so this deletes by id
/// alone and emits no event - a note has no delete-event consumer.
/// </summary>
internal sealed class DeleteNoteHandler(SampleDbContext db)
{
    public async Task<Result> HandleAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var deleted = await db.Notes
            .Where(candidate => candidate.Id == id)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted == 0)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "sample.note_not_found", "No note exists with that id."));
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }
}
