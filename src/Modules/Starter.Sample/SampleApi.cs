using Starter.Sample.CreateNote;
using Starter.Sample.DeleteNote;
using Starter.Sample.GetNote;
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
    DeleteNoteHandler deleteNote) : ISampleApi
{
    public Task<Result<Guid>> CreateNoteAsync(
        Guid ownerUserId,
        string title,
        string body,
        CancellationToken cancellationToken) =>
        createNote.HandleAsync(ownerUserId, title, body, cancellationToken);

    public Task<Result<(Guid Id, Guid OwnerUserId, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        GetNoteAsync(Guid id, CancellationToken cancellationToken) =>
        getNote.HandleAsync(id, cancellationToken);

    public Task<Result> DeleteNoteAsync(Guid id, CancellationToken cancellationToken) =>
        deleteNote.HandleAsync(id, cancellationToken);
}
