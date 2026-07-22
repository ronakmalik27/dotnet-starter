using System.Collections.Frozen;

namespace Starter.Platform.Auth;

/// <summary>
/// The closed catalogue of permission atoms (multi-tenancy.md section 13): the
/// application defines every permission that can exist; a tenant composes its
/// custom roles from this set and never invents one (the GitHub / Auth0 custom-
/// role shape). Each is a stable string key that survives message rewording, so
/// a stored grant keeps meaning across releases.
/// <para>
/// A small OWNER-RESERVED subset (<see cref="OwnerReserved"/>) can never appear
/// in a custom role: cross-cutting tenant control (rename, delete, ownership
/// transfer) stays a system-role capability so it cannot be handed out piecemeal
/// through a scoped grant.
/// </para>
/// </summary>
public static class Permissions
{
    /// <summary>Read the tenant's member roster.</summary>
    public const string MembersRead = "members:read";

    /// <summary>Change member roles and remove members.</summary>
    public const string MembersManage = "members:manage";

    /// <summary>Create, list, and revoke invitations.</summary>
    public const string InvitationsManage = "invitations:manage";

    /// <summary>Update tenant settings (name, slug).</summary>
    public const string SettingsManage = "settings:manage";

    /// <summary>Author custom roles and manage assignments.</summary>
    public const string RolesManage = "roles:manage";

    /// <summary>View seats and usage.</summary>
    public const string SeatsRead = "seats:read";

    /// <summary>Read notes (the Sample worked example).</summary>
    public const string NotesRead = "notes:read";

    /// <summary>Create and edit notes.</summary>
    public const string NotesWrite = "notes:write";

    /// <summary>Delete notes.</summary>
    public const string NotesDelete = "notes:delete";

    /// <summary>Read workspaces. Defined now; its endpoints arrive in increment 6.</summary>
    public const string WorkspacesRead = "workspaces:read";

    /// <summary>Create and archive workspaces. Defined now; its endpoints arrive in increment 6.</summary>
    public const string WorkspacesManage = "workspaces:manage";

    /// <summary>Manage teams and their members. Defined now; its endpoints arrive in increment 7.</summary>
    public const string TeamsManage = "teams:manage";

    /// <summary>Owner-reserved: rename or reconfigure the tenant. Never grantable in a custom role.</summary>
    public const string TenantManage = "tenant:manage";

    /// <summary>Owner-reserved: soft-delete the tenant. Never grantable in a custom role.</summary>
    public const string TenantDelete = "tenant:delete";

    /// <summary>Owner-reserved: transfer ownership. Never grantable in a custom role.</summary>
    public const string TenantTransferOwnership = "tenant:transfer-ownership";

    /// <summary>
    /// Every permission the application ships. A custom role's permission set
    /// must be a subset of this (the catalogue is closed).
    /// </summary>
    public static readonly FrozenSet<string> All = new[]
    {
        MembersRead,
        MembersManage,
        InvitationsManage,
        SettingsManage,
        RolesManage,
        SeatsRead,
        NotesRead,
        NotesWrite,
        NotesDelete,
        WorkspacesRead,
        WorkspacesManage,
        TeamsManage,
        TenantManage,
        TenantDelete,
        TenantTransferOwnership,
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// The permissions reserved to owners: they belong to the Owner system role
    /// only and can never appear in a custom role, so cross-cutting tenant
    /// control is not grantable piecemeal.
    /// </summary>
    public static readonly FrozenSet<string> OwnerReserved = new[]
    {
        TenantManage,
        TenantDelete,
        TenantTransferOwnership,
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>True when <paramref name="permission"/> is a catalogue permission.</summary>
    public static bool IsKnown(string permission) => All.Contains(permission);

    /// <summary>True when <paramref name="permission"/> is owner-reserved (never in a custom role).</summary>
    public static bool IsOwnerReserved(string permission) => OwnerReserved.Contains(permission);
}
