using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Notifications;

/// <summary>
/// The in-app notifications projection (in-app-notifications.md sections 2, 3): a
/// Fast-lane Platform consumer that turns a CURATED subset of domain events into
/// per-recipient <c>platform.notifications</c> inbox rows. It is the targeted
/// sibling of <see cref="Starter.Platform.Events.AuditProjectionConsumer"/> and
/// shares its exact shape: it references no module type (the payload is read by
/// UNTYPED JSON traversal, never a typed module record - the dependency-shape arch
/// test forbids Platform seeing a module type), it resolves the request-style
/// (RLS-bound) <see cref="PlatformDbContext"/> from the passed scope (never the
/// bypass data source), and the dispatcher binds this scope's tenant from the
/// event's tenant_id before this runs, so the insert is bound by row-level security
/// to exactly that tenant.
/// <para>
/// Fast lane, like the audit projection and the webhook fan-out: this consumer is a
/// pure INSERT (no <c>IEmailSender</c>/HTTP call in <see cref="ConsumeAsync"/>,
/// unlike the Slow-lane email consumer), so Fast is correct AND it joins the
/// existing Fast outbox row these four events already carry (audit + webhook)
/// rather than minting a second Slow-lane row per event. A Slow lane would
/// head-of-line-block a badge update behind an unrelated slow email.
/// </para>
/// <para>
/// Dedup is by construction: the unique <c>(source_event_id, recipient_user_id)</c>
/// index means a redelivery (at-least-once) hits the index and is caught as a
/// unique violation this consumer treats as success (the row is already there) -
/// the audit-projection discipline, keyed on the (event, recipient) pair.
/// </para>
/// <para>
/// A CURATED subscription with a per-type recipient rule. There is NO
/// actor-exclusion check: the recipient is whatever the per-type rule reads, and
/// that is the whole story. For the three admin-driven events the recipient is a
/// PAYLOAD field (the affected member), inherently a different user from the acting
/// admin; for <c>tenancy.membership.created</c> the recipient IS the actor, because
/// that event's actor IS the joining member (self-provision or self-accept), and
/// notifying them ("you joined as {role}") is exactly the intent. A blanket
/// <c>if (actor == recipient) skip</c> would be WRONG - it would silently drop every
/// membership.created notification forever.
/// </para>
/// </summary>
internal sealed class NotificationProjectionConsumer : Starter.Platform.Events.IDomainEventConsumer
{
    // The curated event types (in-app-notifications.md section 3). String literals,
    // not a reference to the Tenancy module's TenancyEvents: Platform references no
    // module type (the same reason DeliverableEvents hardcodes the tenancy.* names).
    private const string MembershipCreated = "tenancy.membership.created";
    private const string MemberRoleChanged = "tenancy.member.role_changed";
    private const string TeamMemberAdded = "tenancy.team.member_added";
    private const string OwnershipTransferred = "tenancy.ownership.transferred";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Starter.Platform.Events.Lane Lane => Starter.Platform.Events.Lane.Fast;

    /// <summary>
    /// The CURATED set (in-app-notifications.md section 3), NOT the shared
    /// <c>DeliverableEvents.TenantScoped</c> catalogue the audit projection uses.
    /// These are the events that name exactly one clear recipient USER; every
    /// other event has no single natural recipient and is deliberately not
    /// notified in-app.
    /// </summary>
    public IReadOnlyCollection<string> EventTypes =>
        [MembershipCreated, MemberRoleChanged, TeamMemberAdded, OwnershipTransferred];

    public async Task ConsumeAsync(
        IServiceProvider services,
        Starter.Platform.Events.DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(domainEvent);

        var recipient = ResolveRecipient(domainEvent);
        if (recipient is null)
        {
            // Not a curated type (unreachable through the dispatcher's routing),
            // or a curated event whose recipient field is absent. Nothing to
            // project; treat it as a benign success so the row is marked delivered.
            return;
        }

        var db = services.GetRequiredService<PlatformDbContext>();
        var tenant = services.GetRequiredService<ITenantContext>();
        var clock = services.GetRequiredService<Clock>();
        var now = clock.UtcNow;

        // The transaction is what makes the interceptor set the tenant GUC, so
        // the insert below runs under RLS for the event's tenant.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.Notifications.Add(new NotificationRow
        {
            Id = Ids.NewId(now),
            // Stamped from the tenant context, never from the payload. RLS's
            // WITH CHECK rejects the write if it disagrees with the GUC.
            TenantId = tenant.TenantId,
            RecipientUserId = recipient.Value.RecipientUserId,
            SourceEventId = domainEvent.Id,
            Type = domainEvent.EventType,
            Data = recipient.Value.Data,
            CreatedAt = now,
            ReadAt = null,
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // At-least-once redelivery: a row for this (source_event_id,
            // recipient_user_id) pair already exists. The failed insert aborted
            // this transaction; roll back the empty unit and treat the redelivery
            // as success (idempotent by construction).
            await transaction.RollbackAsync(cancellationToken);
            return;
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// The per-type recipient rule (in-app-notifications.md section 3): maps the
    /// event to its (recipient user, render data), or null to skip. Reads ONLY the
    /// event (ActorUserId, EntityId, and untyped payload fields) - never a
    /// membership query or an "all admins" resolution (a documented grow-into),
    /// so the consumer stays a pure, module-free projection.
    /// </summary>
    private static (Guid RecipientUserId, string Data)? ResolveRecipient(
        Starter.Platform.Events.DomainEventRecord domainEvent)
    {
        using var document = JsonDocument.Parse(domainEvent.Payload);
        var payload = document.RootElement;

        switch (domainEvent.EventType)
        {
            case MembershipCreated:
                // The recipient IS the actor: this event's actor is the joining
                // member themselves. No actor-exclusion check.
                if (domainEvent.ActorUserId is not { } joiningMember)
                {
                    return null;
                }

                return (joiningMember, Serialize(new { role = ReadString(payload, "role") }));

            case MemberRoleChanged:
                // The affected member rides the payload (a different user from the
                // acting admin, who is the event's actor).
                return TryReadGuid(payload, "userId") is { } roleTarget
                    ? (roleTarget, Serialize(new { role = ReadString(payload, "role") }))
                    : null;

            case TeamMemberAdded:
                // The added user rides the payload; the team is the event's entity.
                return TryReadGuid(payload, "userId") is { } addedUser
                    ? (addedUser, Serialize(new { teamId = domainEvent.EntityId }))
                    : null;

            case OwnershipTransferred:
                // The new owner rides the payload; the previous owner is the render
                // datum (the event's actor is the previous owner).
                return TryReadGuid(payload, "newOwnerUserId") is { } newOwner
                    ? (newOwner, Serialize(new { previousOwnerUserId = TryReadGuid(payload, "previousOwnerUserId") }))
                    : null;

            default:
                return null;
        }
    }

    private static string Serialize<T>(T data) => JsonSerializer.Serialize(data, Json);

    private static string? ReadString(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static Guid? TryReadGuid(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
            && Guid.TryParse(value.GetString(), out var parsed)
                ? parsed
                : null;

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
