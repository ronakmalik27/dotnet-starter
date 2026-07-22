using Starter.Platform.Auth;
using Starter.Platform.Tenancy;

namespace Starter.Sample.Domain;

/// <summary>
/// A sample.notes row: the smallest entity that still shows the pattern -
/// a UUIDv7 id minted app-side (SharedKernel Ids), created/updated
/// timestamps stamped from the SharedKernel Clock, an owner id, and no
/// cross-schema navigations. It is <see cref="ITenantOwned"/> (a note belongs
/// to one tenant, enforced by RLS and the query filter) and
/// <see cref="IOwnedResource"/> (within that tenant it is still owned by its
/// creator, the inner authorization check). Copy this as the starting point
/// for a real tenant-owned module entity.
/// </summary>
internal sealed class Note : ITenantOwned, IOwnedResource
{
    public required Guid Id { get; init; }

    /// <summary>The tenant this note belongs to. Stamped from the tenant context on create.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The user who created the note and may read or delete it.</summary>
    public required Guid OwnerUserId { get; init; }

    public required string Title { get; set; }

    public required string Body { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; set; }
}
