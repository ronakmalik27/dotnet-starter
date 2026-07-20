using Starter.Platform.Auth;

namespace Starter.Sample.Domain;

/// <summary>
/// A sample.notes row: the smallest entity that still shows the pattern -
/// a UUIDv7 id minted app-side (SharedKernel Ids), created/updated
/// timestamps stamped from the SharedKernel Clock, an owner id, and no
/// cross-schema navigations. It implements <see cref="IOwnedResource"/>, so
/// the endpoint layer can authorize read/update/delete against the owner
/// per request. Copy this as the starting point for a real module entity.
/// </summary>
internal sealed class Note : IOwnedResource
{
    public required Guid Id { get; init; }

    /// <summary>The user who created the note and may read or delete it.</summary>
    public required Guid OwnerUserId { get; init; }

    public required string Title { get; set; }

    public required string Body { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; set; }
}
