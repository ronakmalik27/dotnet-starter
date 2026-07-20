using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Sample;

/// <summary>
/// The Sample module's domain events. Payloads carry ids and coarse
/// metadata only - never free-text bodies or any user content. The
/// event id is a UUIDv7 minted through the SharedKernel
/// Ids helper, so ordering matches the row it describes.
/// </summary>
internal static class SampleEvents
{
    private const string Module = "sample";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// sample.note.created: a note was created. Carries only the title
    /// length as a coarse size signal - never the title or body text.
    /// </summary>
    public static DomainEventRecord NoteCreated(Guid noteId, int titleLength, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "sample.note.created",
        EntityId = noteId,
        ActorUserId = null,
        Payload = JsonSerializer.Serialize(new { titleLength }, Json),
    };
}
