using Starter.Platform.Tenancy;

namespace Starter.Platform.Notifications;

/// <summary>
/// A <c>platform.notifications</c> row: one in-app notification, projected from a
/// domain event by <c>NotificationProjectionConsumer</c> (in-app-notifications.md
/// section 2). It is the targeted sibling of the audit log - where the audit
/// projection is keyed on the whole tenant, this row is keyed on a single
/// recipient USER within a tenant, so it is that user's inbox item.
/// <para>
/// It is <see cref="ITenantOwned"/>: it carries <c>tenant_id</c> and lives under
/// FORCE row-level security (the standard <c>tenant_isolation</c> policy), so a
/// reader is bound by the same authoritative boundary as every other tenant read.
/// The reader is further narrowed to their own rows by the
/// <c>recipient_user_id = caller</c> predicate on every query. Dedup is by
/// construction: the unique <c>(source_event_id, recipient_user_id)</c> index makes
/// an at-least-once redelivery a benign unique-violation the consumer treats as
/// success. The primary key is a fresh <c>Ids.NewId</c> rather than the source
/// event id, so a single event MAY fan out to several recipients later without an
/// id collision (today each curated event has exactly one recipient).
/// </para>
/// </summary>
internal sealed class NotificationRow : ITenantOwned
{
    /// <summary>Primary key (a fresh UUIDv7 from <c>Ids.NewId</c>), not the source event id.</summary>
    public required Guid Id { get; init; }

    /// <summary>The RLS discriminator, stamped from the event's tenant context on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The user this notification is for (derived from the event, section 3).</summary>
    public required Guid RecipientUserId { get; init; }

    /// <summary>The domain event this was projected from; the dedup key with the recipient.</summary>
    public required Guid SourceEventId { get; init; }

    /// <summary>The notification type (the source event type, e.g. <c>tenancy.member.role_changed</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Render fields (jsonb): ids and scalars only, never PII (the source payload is already PII-free).</summary>
    public required string Data { get; init; }

    /// <summary>When the notification was projected (Clock.UtcNow at consume time).</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Null = unread; set when the recipient marks it read.</summary>
    public DateTimeOffset? ReadAt { get; init; }
}
