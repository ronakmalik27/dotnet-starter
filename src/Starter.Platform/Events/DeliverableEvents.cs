using Starter.Platform.Webhooks;

namespace Starter.Platform.Events;

/// <summary>
/// The tenant-scoped deliverable event catalogue: every event that carries a
/// <c>tenant_id</c>. This is the single list the two Platform fan-out projections share
/// so they can never drift - the audit projection (audit-log.md section 2) and the
/// webhook fan-out (webhooks.md section 3) both subscribe to exactly this set. Adding a
/// tenant-scoped event type here makes it both audited AND webhook-deliverable in one
/// place; the catalogue-completeness test asserts every discovered event type is in this
/// set or the named not-audited set.
/// </summary>
internal static class DeliverableEvents
{
    /// <summary>The tenant-scoped catalogue (all <c>tenancy.*</c>, the tenant-scoped <c>platform.impersonation.*</c>, the webhook lifecycle, and the sample module).</summary>
    public static readonly IReadOnlyCollection<string> TenantScoped =
    [
        // tenancy.* control plane
        "tenancy.tenant.created",
        "tenancy.membership.created",
        "tenancy.member.role_changed",
        "tenancy.member.removed",
        "tenancy.invitation.created",
        "tenancy.invitation.revoked",
        "tenancy.tenant.settings_updated",
        "tenancy.ownership.transferred",
        "tenancy.tenant.soft_deleted",
        "tenancy.tenant.suspended",
        "tenancy.tenant.reactivated",
        "tenancy.tenant.plan_changed",
        // A bulk data export is a tenant-scoped, audited, webhook-deliverable access
        // (data-export-and-erasure.md section 6): a security team may want to know.
        "tenancy.tenant.data_exported",
        "tenancy.workspace.created",
        "tenancy.workspace.renamed",
        "tenancy.workspace.archived",
        "tenancy.workspace.unarchived",
        "tenancy.role.created",
        "tenancy.role.updated",
        "tenancy.role.deleted",
        "tenancy.role_assignment.granted",
        "tenancy.role_assignment.revoked",
        "tenancy.team.created",
        "tenancy.team.renamed",
        "tenancy.team.deleted",
        "tenancy.team.member_added",
        "tenancy.team.member_removed",
        "tenancy.service_account.created",
        "tenancy.service_account.rotated",
        "tenancy.service_account.revoked",
        // enterprise SSO config / domain-claim changes (sso-and-scim.md section 6):
        // tenant-scoped, so audited AND webhook-deliverable like the rest.
        "tenancy.sso.configured",
        // SCIM token rotation and directory-driven member deactivate/reactivate
        // (sso-and-scim.md section 5): tenant-scoped, so audited AND
        // webhook-deliverable like the rest. A directory offboard cutting tenant
        // access is exactly the change a security team wants on the record.
        "tenancy.scim.token_rotated",
        "tenancy.member.suspended",
        "tenancy.member.reactivated",
        // webhook endpoint lifecycle (webhooks.md section 8): defined in Platform
        // (WebhookEvents) because the feature cannot reference the Tenancy module, but
        // tenant-scoped like the rest.
        WebhookEvents.EndpointCreatedType,
        WebhookEvents.EndpointUpdatedType,
        WebhookEvents.EndpointDeletedType,
        WebhookEvents.SecretRotatedType,
        // feature-flag override changes (feature-flags.md section 5): defined in
        // Platform (FeatureFlagEvents) because the feature cannot reference the
        // Tenancy module, but tenant-scoped like the rest.
        Data.FeatureFlagEvents.OverrideSetType,
        Data.FeatureFlagEvents.OverrideClearedType,
        // tenant-scoped platform events (carry the target tenant)
        "platform.impersonation.started",
        "platform.impersonation.ended",
        // sample module
        "sample.note.created",
    ];
}
