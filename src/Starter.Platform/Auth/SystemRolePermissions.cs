using System.Collections.Frozen;

namespace Starter.Platform.Auth;

/// <summary>
/// The system-role permission sets (multi-tenancy.md section 13): the fixed
/// <see cref="TenantRole"/> ladder (owner &gt; admin &gt; member) expressed as
/// permission sets, defined in CODE and never stored as rows (so
/// <c>tenancy.roles</c> holds custom roles only and needs no null-tenant RLS
/// exception). These sets REPRODUCE Part I behavior exactly: they are derived
/// from the tenant-role thresholds Part I's tenant-admin endpoints required, so
/// migrating those endpoints from <c>RequireTenantRole</c> to
/// <c>RequirePermission</c> changes the mechanism, not who is allowed.
/// <list type="bullet">
///   <item><b>Member</b>: the reads a Part I member had (the member roster and
///   seats), own-resource note capabilities, and viewing workspaces.</item>
///   <item><b>Admin</b>: everything a member has, plus member management,
///   invitations, settings, custom-role authoring, workspace management, team
///   management, and reading the tenant audit log - the full Part I admin surface
///   plus creating/archiving workspaces, managing teams, and audit-log reads.</item>
///   <item><b>Owner</b>: everything an admin has, plus the owner-reserved
///   capabilities (rename, delete, ownership transfer) that are never grantable
///   through a custom role.</item>
/// </list>
/// Admin is a strict superset of Member and Owner of Admin, matching how the
/// ladder already ranks (a higher role can do everything a lower one can).
/// </summary>
public static class SystemRolePermissions
{
    private static readonly FrozenSet<string> MemberSet = new[]
    {
        Permissions.MembersRead,
        Permissions.SeatsRead,
        Permissions.NotesRead,
        Permissions.NotesWrite,
        Permissions.NotesDelete,
        // Viewing workspaces is a member-level read (multi-tenancy.md section 12).
        Permissions.WorkspacesRead,
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> AdminSet = MemberSet
        .Concat(
        [
            Permissions.MembersManage,
            Permissions.InvitationsManage,
            Permissions.SettingsManage,
            Permissions.RolesManage,
            // Creating and archiving workspaces is admin work (section 12); Owner
            // inherits it as a strict superset of Admin below.
            Permissions.WorkspacesManage,
            // Managing teams (and their members) is admin work (section 14): a
            // team is a tenant-owned principal that can hold grants.
            Permissions.TeamsManage,
            // Reading the tenant audit log is admin work (audit-log.md section 7):
            // tenant Admins and Owners can read it, Members cannot. It is grantable
            // in a custom role like any non-owner-reserved permission, so a tenant
            // can mint a read-only Auditor role.
            Permissions.AuditRead,
            // Managing service accounts and their API keys is admin work
            // (service-accounts.md section 7): Admins and Owners manage keys. It is
            // grantable in a custom role like any non-owner-reserved permission -
            // but never to a service account (Permissions.NotServiceAccountGrantable).
            Permissions.ApiKeysManage,
            // Managing outbound webhooks is admin work (webhooks.md section 7): Admins and
            // Owners register endpoints, rotate secrets, and replay deliveries. Grantable
            // in a custom role like any non-owner-reserved permission, and (unlike keys)
            // grantable to a service account too - it is not self-escalation.
            Permissions.WebhooksManage,
            // Managing the tenant's own feature-flag overrides is admin work
            // (feature-flags.md section 5): Admins and Owners set/clear overrides for
            // operator-overridable flags. Grantable in a custom role like any
            // non-owner-reserved permission, and (like webhooks) grantable to a service
            // account too - it is not self-escalation.
            Permissions.FeatureFlagsManage,
            // Exporting the whole tenant data set is admin work (data-export-and-erasure.md
            // section 3): Admins and Owners self-serve the GDPR Art. 15/20 portability
            // bundle. Grantable in a custom role like any non-owner-reserved permission -
            // but never to a service account (Permissions.NotServiceAccountGrantable).
            Permissions.DataExport,
        ])
        .ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> OwnerSet = AdminSet
        .Concat(
        [
            Permissions.TenantManage,
            Permissions.TenantDelete,
            Permissions.TenantTransferOwnership,
        ])
        .ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// The permission set a system role confers tenant-wide. An unknown role
    /// (never produced by <see cref="TenantRole"/>) is the empty set, fail-closed.
    /// </summary>
    public static IReadOnlySet<string> For(TenantRole role) => role switch
    {
        TenantRole.Member => MemberSet,
        TenantRole.Admin => AdminSet,
        TenantRole.Owner => OwnerSet,
        _ => FrozenSet<string>.Empty,
    };
}
