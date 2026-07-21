using Starter.Sample.CreateNote;
using Starter.Sample.DeleteNote;
using Starter.Sample.GetNote;
using Starter.Sample.ListNotes;
using Starter.Platform.Http;
using Starter.SharedKernel;

namespace Starter.Sample;

/// <summary>
/// The module facade: one internal class carrying the public interface,
/// delegating to the per-use-case slice handlers (the same vertical-slice
/// shape as the Identity module's IdentityApi).
/// </summary>
internal sealed class SampleApi(
    CreateNoteHandler createNote,
    GetNoteHandler getNote,
    DeleteNoteHandler deleteNote,
    ListNotesHandler listNotes) : ISampleApi
{
    public Task<Result<Guid>> CreateNoteAsync(
        Guid ownerUserId,
        string title,
        string body,
        CancellationToken cancellationToken,
        IIdempotentTransaction? idempotentTransaction = null) =>
        createNote.HandleAsync(ownerUserId, title, body, cancellationToken, idempotentTransaction);

    public Task<Result<(Guid Id, Guid OwnerUserId, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        GetNoteAsync(Guid id, CancellationToken cancellationToken) =>
        getNote.HandleAsync(id, cancellationToken);

    public Task<Result> DeleteNoteAsync(Guid id, CancellationToken cancellationToken) =>
        deleteNote.HandleAsync(id, cancellationToken);

    public Task<Result<(IReadOnlyList<(Guid Id, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)> Items, string? NextCursor)>>
        ListNotesAsync(Guid ownerUserId, int limit, string? cursor, CancellationToken cancellationToken) =>
        listNotes.HandleAsync(ownerUserId, limit, cursor, cancellationToken);
}
