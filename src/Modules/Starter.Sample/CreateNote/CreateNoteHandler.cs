using Starter.Sample.Domain;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Sample.CreateNote;

/// <summary>
/// Creates a note and emits sample.note.created on the outbox in the same
/// transaction as the row: the state, the domain_events spine row, and
/// any outbox rows commit or roll back together. This is the worked
/// example of the transactional-outbox pattern for a new module.
/// </summary>
internal sealed class CreateNoteHandler(SampleDbContext db, OutboxWriter outbox, Clock clock)
{
    public async Task<Result<Guid>> HandleAsync(
        Guid ownerUserId,
        string title,
        string body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(title);
        ArgumentNullException.ThrowIfNull(body);

        title = title.Trim();
        if (title.Length == 0)
        {
            return new Error(ErrorKind.Validation, "sample.title_required", "A note title is required.");
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return new Error(ErrorKind.Validation, "sample.body_required", "A note body is required.");
        }

        var now = clock.UtcNow;
        var note = new Note
        {
            Id = Ids.NewId(now),
            OwnerUserId = ownerUserId,
            Title = title,
            Body = body,
            CreatedAt = now,
            UpdatedAt = now,
        };

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.Notes.Add(note);
        await outbox.EnqueueAsync(db, SampleEvents.NoteCreated(note.Id, title.Length, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return note.Id;
    }
}
