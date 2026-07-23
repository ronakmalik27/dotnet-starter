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
    /// platform.plan.created: a super-admin created a plan-catalogue entry
    /// (billing-and-entitlements.md sections 6, 7). A null-tenant operator action,
    /// audited SYNCHRONOUSLY through the platform audit writer in the same
    /// transaction as the catalogue write - never by the async tenant projection.
    /// The plan has no Guid identity (its key is the pk), so the entity id is empty
    /// and the key rides the payload (a scalar, no PII).
    /// </summary>
    public static DomainEventRecord PlanCreated(
        string planKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.plan.created",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { planKey }, Json),
        };

    /// <summary>
    /// platform.plan.updated: a super-admin edited a plan-catalogue entry (name,
    /// features, permissions, limits, or default). Same null-tenant, synchronously
    /// audited shape as <see cref="PlanCreated"/>.
    /// </summary>
    public static DomainEventRecord PlanUpdated(
        string planKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.plan.updated",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { planKey }, Json),
        };

    /// <summary>
    /// platform.feature_flag.created: a super-admin created a feature-flag catalogue
    /// entry (feature-flags.md section 5). A null-tenant operator action, audited
    /// SYNCHRONOUSLY through the platform audit writer in the same transaction as the
    /// catalogue write - never by the async tenant projection. The flag has no Guid
    /// identity (its key is the pk), so the entity id is empty and the key rides the
    /// payload (a scalar, no PII).
    /// </summary>
    public static DomainEventRecord FeatureFlagCreated(
        string flagKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.feature_flag.created",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { flagKey }, Json),
        };

    /// <summary>
    /// platform.feature_flag.updated: a super-admin edited a feature-flag catalogue
    /// entry (default, rollout, overridable, or archive). Same null-tenant,
    /// synchronously audited shape as <see cref="FeatureFlagCreated"/>.
    /// </summary>
    public static DomainEventRecord FeatureFlagUpdated(
        string flagKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.feature_flag.updated",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { flagKey }, Json),
        };

    /// <summary>
    /// platform.role_template.created: a super-admin created a role-template
    /// catalogue entry (role-templates-and-policy-defaults.md sections 2, 6). A
    /// null-tenant operator action, audited SYNCHRONOUSLY through the platform audit
    /// writer in the same transaction as the catalogue write - never by the async
    /// tenant projection. The template has no Guid identity (its key is the pk), so
    /// the entity id is empty and the key rides the payload (a scalar, no PII).
    /// </summary>
    public static DomainEventRecord RoleTemplateCreated(
        string templateKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.role_template.created",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { templateKey }, Json),
        };

    /// <summary>
    /// platform.role_template.updated: a super-admin edited a role-template
    /// catalogue entry (name, description, permissions, or assignable scopes). Same
    /// null-tenant, synchronously audited shape as <see cref="RoleTemplateCreated"/>.
    /// Editing a template does NOT retro-change already-seeded tenant copies.
    /// </summary>
    public static DomainEventRecord RoleTemplateUpdated(
        string templateKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.role_template.updated",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { templateKey }, Json),
        };

    /// <summary>
    /// platform.role_template.deleted: a super-admin deleted a role-template
    /// catalogue entry. Same null-tenant, synchronously audited shape as
    /// <see cref="RoleTemplateCreated"/>. Already-seeded tenant copies are the
    /// tenants' own roles and are untouched.
    /// </summary>
    public static DomainEventRecord RoleTemplateDeleted(
        string templateKey,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.role_template.deleted",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { templateKey }, Json),
        };

    /// <summary>
    /// platform.policy.updated: a super-admin edited the install-wide policy-defaults
    /// singleton (password / session / lockout floors,
    /// role-templates-and-policy-defaults.md sections 3, 6). A null-tenant operator
    /// action, audited SYNCHRONOUSLY through the platform audit writer in the same
    /// transaction as the singleton write - never by the async tenant projection. The
    /// singleton has no Guid identity, so the entity id is empty and the payload
    /// carries no fields (the values are on the row; the event records only that a
    /// change happened, by whom).
    /// </summary>
    public static DomainEventRecord PolicyUpdated(
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.policy.updated",
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// platform.tenant.erased: a super-admin hard-deleted (erased) a tenant, purging
    /// its rows (data-export-and-erasure.md sections 5, 6, GDPR Art. 17). Written
    /// SYNCHRONOUSLY to platform.platform_audit_log in the SAME bypass transaction as
    /// the purge - it is NOT a tenant-scoped domain event: a tenant-scoped event would
    /// ride the tenant's own outbox / audit log, which the erasure is destroying. The
    /// platform log is the surviving home. Actor is the acting super-admin; the entity
    /// is the erased tenant.
    /// </summary>
    public static DomainEventRecord TenantErased(
        Guid tenantId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "platform.tenant.erased",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            // The platform audit log has no tenant_id / entity_id column, so the
            // erased tenant id rides the payload (a scalar, no PII) to keep the
            // durable record self-identifying.
            Payload = JsonSerializer.Serialize(new { tenantId }, Json),
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
