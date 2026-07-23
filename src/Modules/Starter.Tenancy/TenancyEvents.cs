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

    /// <summary>
    /// tenancy.tenant.data_exported: a tenant admin exported the tenant's whole data
    /// set (data-export-and-erasure.md section 6, GDPR Art. 15/20). Tenant-scoped,
    /// audited, and webhook-deliverable, so a bulk data access is on the record. Actor
    /// is the exporting admin; the payload is a per-section row-count summary
    /// (<c>sections</c>), never a copy of the exported data.
    /// </summary>
    public static DomainEventRecord TenantDataExported(
        Guid tenantId,
        Guid actorUserId,
        IReadOnlyDictionary<string, int>? sectionCounts,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.data_exported",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { sections = sectionCounts }, Json),
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

    /// <summary>
    /// tenancy.tenant.suspended: a platform admin suspended the tenant
    /// (status -> suspended). Actor is the acting platform admin; the event is
    /// tenant-scoped (tenant_id = the target), so it lands on the tenant's spine.
    /// </summary>
    public static DomainEventRecord TenantSuspended(
        Guid tenantId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.suspended",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.tenant.reactivated: a platform admin reactivated a suspended
    /// tenant (status -> active). Actor is the acting platform admin.
    /// </summary>
    public static DomainEventRecord TenantReactivated(
        Guid tenantId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.reactivated",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.tenant.plan_changed: a super-admin (or, later, a payment-provider
    /// callback) assigned or changed the tenant's plan
    /// (billing-and-entitlements.md section 6). Tenant-scoped (tenant_id = the
    /// target), so it lands on the tenant's audit spine AND is webhook-deliverable.
    /// Carries the old and new plan keys (scalars, no PII); oldPlan is null when the
    /// tenant had no plan.
    /// </summary>
    public static DomainEventRecord TenantPlanChanged(
        Guid tenantId,
        string? oldPlan,
        string newPlan,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.tenant.plan_changed",
            EntityId = tenantId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { oldPlan, newPlan }, Json),
        };

    /// <summary>
    /// tenancy.workspace.created: a new workspace scope was created inside the
    /// tenant. Actor is the creator; the coarse slug rides the payload.
    /// </summary>
    public static DomainEventRecord WorkspaceCreated(
        Guid workspaceId,
        string slug,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.workspace.created",
            EntityId = workspaceId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { slug }, Json),
        };

    /// <summary>tenancy.workspace.renamed: an admin renamed a workspace.</summary>
    public static DomainEventRecord WorkspaceRenamed(
        Guid workspaceId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.workspace.renamed",
            EntityId = workspaceId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.workspace.archived: an admin archived a workspace (active ->
    /// archived), so its resources go read-only and its scoped grants stop
    /// conferring access, but nothing is destroyed (section 20, reversible).
    /// </summary>
    public static DomainEventRecord WorkspaceArchived(
        Guid workspaceId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.workspace.archived",
            EntityId = workspaceId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.workspace.unarchived: an admin reactivated an archived workspace
    /// (archived -> active), so its resources are writable again and its scoped
    /// grants confer once more (section 20 - archive is reversible).
    /// </summary>
    public static DomainEventRecord WorkspaceUnarchived(
        Guid workspaceId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.workspace.unarchived",
            EntityId = workspaceId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.role.created: a tenant admin authored a custom role. Actor is the
    /// author; the coarse role key rides the payload (never any permission-set
    /// detail beyond the key).
    /// </summary>
    public static DomainEventRecord RoleCreated(
        Guid roleId,
        string key,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.role.created",
            EntityId = roleId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { key }, Json),
        };

    /// <summary>tenancy.role.updated: a tenant admin edited a custom role's name, description, or permissions.</summary>
    public static DomainEventRecord RoleUpdated(
        Guid roleId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.role.updated",
            EntityId = roleId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>tenancy.role.deleted: a tenant admin deleted a custom role that had no assignments.</summary>
    public static DomainEventRecord RoleDeleted(
        Guid roleId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.role.deleted",
            EntityId = roleId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.role_assignment.granted: a custom role was granted to a principal
    /// at a scope. Actor is the granter; the role and the principal ride the
    /// payload (ids only).
    /// </summary>
    public static DomainEventRecord RoleAssignmentGranted(
        Guid assignmentId,
        Guid roleId,
        Guid principalId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.role_assignment.granted",
            EntityId = assignmentId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { roleId, principalId }, Json),
        };

    /// <summary>tenancy.role_assignment.revoked: a custom-role grant was revoked from a principal.</summary>
    public static DomainEventRecord RoleAssignmentRevoked(
        Guid assignmentId,
        Guid roleId,
        Guid principalId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.role_assignment.revoked",
            EntityId = assignmentId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { roleId, principalId }, Json),
        };

    /// <summary>
    /// tenancy.team.created: a tenant admin created a team (a principal that can
    /// hold grants, section 14). Actor is the creator; the coarse slug rides the
    /// payload.
    /// </summary>
    public static DomainEventRecord TeamCreated(
        Guid teamId,
        string slug,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.team.created",
            EntityId = teamId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { slug }, Json),
        };

    /// <summary>tenancy.team.renamed: a tenant admin renamed a team.</summary>
    public static DomainEventRecord TeamRenamed(
        Guid teamId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.team.renamed",
            EntityId = teamId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.team.deleted: a tenant admin deleted a team; its grants were removed
    /// first so none dangles (section 20), and its team_members cascaded with it.
    /// </summary>
    public static DomainEventRecord TeamDeleted(
        Guid teamId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.team.deleted",
            EntityId = teamId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.team.member_added: a user was added to a team, so the team's grants
    /// confer to them on their next request (section 14). Actor is the admin; the
    /// added user rides the payload.
    /// </summary>
    public static DomainEventRecord TeamMemberAdded(
        Guid teamId,
        Guid userId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.team.member_added",
            EntityId = teamId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { userId }, Json),
        };

    /// <summary>
    /// tenancy.team.member_removed: a user was removed from a team, so the team's
    /// grants stop conferring to them on their next request (section 14). Actor is
    /// the admin; the removed user rides the payload.
    /// </summary>
    public static DomainEventRecord TeamMemberRemoved(
        Guid teamId,
        Guid userId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.team.member_removed",
            EntityId = teamId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { userId }, Json),
        };

    /// <summary>
    /// tenancy.service_account.created: an admin minted a service account
    /// (service-accounts.md section 7). Actor is the creating admin; the coarse
    /// name rides the payload. The raw key is NEVER on the payload - it is
    /// returned once in the HTTP response and never persisted anywhere else.
    /// </summary>
    public static DomainEventRecord ServiceAccountCreated(
        Guid serviceAccountId,
        string name,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.service_account.created",
            EntityId = serviceAccountId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { name }, Json),
        };

    /// <summary>
    /// tenancy.service_account.rotated: an admin rotated a service account's key,
    /// so the old secret stopped working immediately (service-accounts.md section
    /// 7). Actor is the admin; no payload beyond the entity - the new key is never
    /// on the payload.
    /// </summary>
    public static DomainEventRecord ServiceAccountRotated(
        Guid serviceAccountId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.service_account.rotated",
            EntityId = serviceAccountId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };

    /// <summary>
    /// tenancy.service_account.revoked: an admin revoked a service account, so its
    /// key fails to resolve on the next request (service-accounts.md section 7).
    /// Actor is the admin; no payload beyond the entity.
    /// </summary>
    public static DomainEventRecord ServiceAccountRevoked(
        Guid serviceAccountId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.service_account.revoked",
            EntityId = serviceAccountId,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { }, Json),
        };
}
