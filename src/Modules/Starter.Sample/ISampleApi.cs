using Starter.SharedKernel;

namespace Starter.Sample;

/// <summary>
/// The only public surface of the Sample module (ADR-0011): the composition
/// layer (Starter.Api) composes HTTP endpoints over these commands - modules
/// never self-host routes. Signatures use primitives and SharedKernel /
/// platform contract types only, so the module exports no other public type
/// (the architecture tests enforce this). The get-by-id read returns a
/// named tuple rather than a module-defined DTO for the same reason: a
/// richer contract would live in a shared contracts assembly, keeping the
/// module surface at exactly its interface plus bootstrap class.
/// </summary>
public interface ISampleApi
{
    /// <summary>
    /// Creates a note and returns its id. Emits sample.note.created on the
    /// transactional outbox in the same transaction as the row (INV-8), so
    /// the demonstration of the outbox pattern is end to end. Failures are
    /// Validation only (empty title or body).
    /// </summary>
    Task<Result<Guid>> CreateNoteAsync(string title, string body, CancellationToken cancellationToken);

    /// <summary>
    /// Reads a note by id. An unknown id is a NotFound failure; success
    /// carries the note's fields as a named tuple.
    /// </summary>
    Task<Result<(Guid Id, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        GetNoteAsync(Guid id, CancellationToken cancellationToken);
}
