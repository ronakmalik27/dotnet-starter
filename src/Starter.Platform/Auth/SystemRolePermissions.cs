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
///   seats) plus own-resource note capabilities.</item>
///   <item><b>Admin</b>: everything a member has, plus member management,
///   invitations, settings, and custom-role authoring - the full Part I admin
///   surface.</item>
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
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> AdminSet = MemberSet
        .Concat(
        [
            Permissions.MembersManage,
            Permissions.InvitationsManage,
            Permissions.SettingsManage,
            Permissions.RolesManage,
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
