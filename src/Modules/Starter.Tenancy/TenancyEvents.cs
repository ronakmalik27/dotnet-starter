using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's domain events. Payloads carry ids and coarse metadata
/// only - never a secret. These are tenant-scoped events: OutboxWriter stamps
/// tenant_id from the tenant the enqueue runs under (the provisioner's context
/// is resolved to the new tenant), so each row lands with tenant_id = the new
/// tenant without the module setting it.
/// </summary>
internal static class TenancyEvents
{
    private const string Module = "tenancy";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// tenancy.tenant.created: a new tenant boundary was established. Actor is
    /// the creating user (the first owner). No payload beyond that by design.
    /// </summary>
    public static DomainEventRecord TenantCreated(Guid tenantId, Guid createdBy, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "tenancy.tenant.created",
        EntityId = tenantId,
        ActorUserId = createdBy,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    /// <summary>
    /// tenancy.membership.created: a user joined a tenant with a role. Carries
    /// the coarse role only - never any credential or contact detail.
    /// </summary>
    public static DomainEventRecord MembershipCreated(
        Guid membershipId,
        Guid tenantId,
        Guid userId,
        string role,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.membership.created",
            EntityId = membershipId,
            ActorUserId = userId,
            Payload = JsonSerializer.Serialize(new { role }, Json),
        };

    /// <summary>
    /// tenancy.member.role_changed: an admin changed a member's role. Actor is
    /// the admin; the affected user and the new role ride the payload.
    /// </summary>
    public static DomainEventRecord MemberRoleChanged(
        Guid membershipId,
        Guid userId,
        string role,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.member.role_changed",
            EntityId = membershipId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { userId, role }, Json),
        };

    /// <summary>
    /// tenancy.member.removed: an admin removed a member (or a member removed
    /// themselves). Actor is the caller; the removed user rides the payload.
    /// </summary>
    public static DomainEventRecord MemberRemoved(
        Guid membershipId,
        Guid userId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.member.removed",
            EntityId = membershipId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { userId }, Json),
        };

    /// <summary>
    /// tenancy.invitation.created: an admin invited an email with a role. The raw
    /// token is NEVER on the payload - it reaches the invitee only through the
    /// emailed link. Carries the coarse role only, never the address.
    /// </summary>
    public static DomainEventRecord InvitationCreated(
        Guid invitationId,
        string role,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.invitation.created",
            EntityId = invitationId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { role }, Json),
        };

    /// <summary>tenancy.invitation.revoked: an admin revoked a pending invitation.</summary>
    public static DomainEventRecord InvitationRevoked(
        Guid invitationId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.invitation.revoked",
            EntityId = invitationId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>tenancy.tenant.settings_updated: an admin changed the tenant name and/or slug.</summary>
    public static DomainEventRecord TenantSettingsUpdated(
        Guid tenantId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.settings_updated",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.ownership.transferred: the owner handed ownership to another
    /// member and stepped down to admin (single-owner model). Actor is the
    /// previous owner; the new owner rides the payload.
    /// </summary>
    public static DomainEventRecord OwnershipTransferred(
        Guid tenantId,
        Guid newOwnerUserId,
        Guid previousOwnerUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.ownership.transferred",
            EntityId = tenantId,
            ActorUserId = previousOwnerUserId,
            Payload = JsonSerializer.Serialize(new { newOwnerUserId, previousOwnerUserId }, Json),
        };

    /// <summary>tenancy.tenant.soft_deleted: the owner soft-deleted the tenant (status -> deleted).</summary>
    public static DomainEventRecord TenantSoftDeleted(
        Guid tenantId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.soft_deleted",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };
}
