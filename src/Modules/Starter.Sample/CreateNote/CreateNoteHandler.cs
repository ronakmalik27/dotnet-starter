using Microsoft.EntityFrameworkCore;
using Starter.Sample.Domain;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Sample.CreateNote;

/// <summary>
/// Creates a note and emits sample.note.created on the outbox in the same
/// transaction as the row: the state, the domain_events spine row, and
/// any outbox rows commit or roll back together. This is the worked
/// example of the transactional-outbox pattern for a new module.
/// <para>
/// It is also the worked example of enlisting a module write onto the
/// idempotency filter's transaction. When the endpoint is behind
/// RequireIdempotency the filter opens the transaction, exposes it via
/// <see cref="IIdempotentTransaction"/>, and commits after the handler
/// succeeds. In that mode the handler must NOT open or commit a transaction
/// of its own; it stages its writes on the filter's transaction so the note,
/// the spine row, the outbox rows, and the filter's stored idempotency
/// response all commit atomically. A crash between two separate commits
/// (the double-create bug) is impossible because there is only one commit.
/// Absent the filter, the handler owns the transaction end to end.
/// </para>
/// </summary>
internal sealed class CreateNoteHandler(SampleDbContext db, OutboxWriter outbox, Clock clock, ITenantContext tenant)
{
    public async Task<Result<Guid>> HandleAsync(
        Guid ownerUserId,
        string title,
        string body,
        CancellationToken cancellationToken,
        IIdempotentTransaction? idempotentTransaction = null)
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
            // Stamped from the tenant context, never from client input. RLS's
            // WITH CHECK rejects the INSERT if this disagrees with the GUC.
            TenantId = tenant.TenantId,
            OwnerUserId = ownerUserId,
            Title = title,
            Body = body,
            CreatedAt = now,
            UpdatedAt = now,
        };

        if (idempotentTransaction is not null)
        {
            // Enlist onto the idempotency filter's open transaction instead of
            // opening our own. Build a fresh SampleDbContext bound to the
            // filter's connection and transaction - the exact mirror of how
            // OutboxWriter builds its PlatformDbContext - stage the note plus
            // the spine and outbox rows on it, and SaveChanges. There is NO
            // commit here: the filter owns it, so the note, its domain_events
            // row, its outbox rows, and the stored idempotency response commit
            // as one unit. (The connection/transaction lifetime is the
            // filter's; this context only borrows them, so it is not disposed
            // with a rollback of its own.) ForConnection carries the tenant
            // interceptor, so enlisting the transaction sets the RLS GUC on the
            // shared connection before the note INSERT; the enlisted context
            // gets the SAME tenant so its query filter and the GUC agree.
            var options = StarterDbContextOptions.ForConnection<SampleDbContext>(
                idempotentTransaction.Connection).Options;
            await using var enlisted = new SampleDbContext(options, tenant);
            await enlisted.Database.UseTransactionAsync(idempotentTransaction.Transaction, cancellationToken);

            enlisted.Notes.Add(note);
            await outbox.EnqueueAsync(
                enlisted, SampleEvents.NoteCreated(note.Id, title.Length, now), cancellationToken);
            await enlisted.SaveChangesAsync(cancellationToken);

            return note.Id;
        }

        // Standalone: own the transaction end to end (open, write, commit).
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.Notes.Add(note);
        await outbox.EnqueueAsync(db, SampleEvents.NoteCreated(note.Id, title.Length, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return note.Id;
    }
}
