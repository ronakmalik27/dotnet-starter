using Starter.Platform.Tenancy;

namespace Starter.Sample.Domain;

/// <summary>
/// A sample.note_index row: the worked example of a tenant-owned read model a
/// domain-event consumer maintains. On sample.note.created the consumer reads
/// the note (bound by RLS to the event's tenant) and upserts one row here,
/// recording the note's title length and how many notes are visible to that
/// tenant. Both the read and this write run under the tenant GUC, so the
/// projection can only ever reflect its own tenant - the consumer-isolation
/// proof. Keyed by the note id; <see cref="ITenantOwned"/> like the note.
/// </summary>
internal sealed class NoteIndex : ITenantOwned
{
    public required Guid NoteId { get; init; }

    /// <summary>The owning tenant. Stamped from the tenant context on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The indexed note's title length (from the event payload / the read note).</summary>
    public required int TitleLength { get; set; }

    /// <summary>How many notes were visible to this tenant when the projection was built.</summary>
    public required int VisibleNoteCount { get; set; }

    /// <summary>When the projection row was last written.</summary>
    public required DateTimeOffset IndexedAt { get; set; }
}
