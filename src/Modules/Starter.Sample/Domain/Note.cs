namespace Starter.Sample.Domain;

/// <summary>
/// A sample.notes row: the smallest entity that still shows the pattern -
/// a UUIDv7 id minted app-side (SharedKernel Ids), created/updated
/// timestamps stamped from the SharedKernel Clock, and no cross-schema
/// navigations. Copy this as the starting point for a real module entity.
/// </summary>
internal sealed class Note
{
    public required Guid Id { get; init; }

    public required string Title { get; set; }

    public required string Body { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; set; }
}
