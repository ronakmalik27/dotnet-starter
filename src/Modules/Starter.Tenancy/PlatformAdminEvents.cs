using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The platform super-admin plane's domain events (multi-tenancy.md section 7).
/// These are platform-level, not tenant-scoped: the admin-grant / revoke events
/// carry no tenant (OutboxWriter stamps tenant_id null because they enqueue
/// under the no-tenant context), and the impersonation events carry the target
/// tenant so a tenant's audit trail shows who impersonated into it. Payloads
/// carry ids only - never the impersonation reason, which lives on the grant
/// row and off the append-only event spine (multi-tenancy.md: NO secrets on
/// payloads).
/// </summary>
internal static class PlatformAdminEvents
{
    private const string Module = "platform";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// platform.admin.granted: a platform admin granted platform power to a user.
    /// Actor is the granting admin; the entity is the new admin's user id.
    /// </summary>
    public static DomainEventRecord PlatformAdminGranted(
        Guid targetUserId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.admin.granted",
            EntityId = targetUserId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// platform.admin.revoked: a platform admin revoked another's platform power.
    /// Actor is the revoking admin; the entity is the removed admin's user id.
    /// </summary>
    public static DomainEventRecord PlatformAdminRevoked(
        Guid targetUserId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.admin.revoked",
            EntityId = targetUserId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// platform.impersonation.started: an admin started an impersonation session.
    /// Written in the SAME transaction as the grant row, so no impersonation
    /// token exists without this audit record. Actor is the acting admin; the
    /// entity is the grant id; the payload names the target tenant and (when
    /// present) the target user - never the reason.
    /// </summary>
    public static DomainEventRecord ImpersonationStarted(
        Guid grantId,
        Guid adminUserId,
        Guid targetTenantId,
        Guid? targetUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.impersonation.started",
            EntityId = grantId,
            ActorUserId = adminUserId,
            Payload = JsonSerializer.Serialize(new { targetTenantId, targetUserId }, Json),
        };

    /// <summary>
    /// platform.impersonation.ended: an admin ended an impersonation session
    /// early (or it was ended idempotently). Actor is the acting admin; the
    /// entity is the grant id.
    /// </summary>
    public static DomainEventRecord ImpersonationEnded(
        Guid grantId,
        Guid adminUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.impersonation.ended",
            EntityId = grantId,
            ActorUserId = adminUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };
}
