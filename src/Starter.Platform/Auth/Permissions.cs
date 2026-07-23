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

    /// <summary>Read the tenant's audit log (audit-log.md section 7).</summary>
    public const string AuditRead = "audit:read";

    /// <summary>
    /// Manage service accounts and their API keys (service-accounts.md section 7):
    /// create, list, rotate, and revoke. In the Admin system-role set and grantable
    /// in a custom role like any non-owner-reserved permission - but never to a
    /// service-account principal (<see cref="NotServiceAccountGrantable"/>).
    /// </summary>
    public const string ApiKeysManage = "api-keys:manage";

    /// <summary>
    /// Manage outbound webhook endpoints (webhooks.md section 7): register, list, update,
    /// rotate the signing secret, delete, read the delivery log, and replay. In the Admin
    /// system-role set and grantable in a custom role like any non-owner-reserved
    /// permission. Unlike <see cref="RolesManage"/> / <see cref="ApiKeysManage"/> it is NOT
    /// self-escalation (a webhook forwards events to an external URL bounded by the SSRF
    /// guard; it cannot expand the caller's own authority), so it is NOT in
    /// <see cref="NotServiceAccountGrantable"/> - a service account may manage webhooks.
    /// </summary>
    public const string WebhooksManage = "webhooks:manage";

    /// <summary>
    /// Manage the tenant's own feature-flag overrides (feature-flags.md section 5):
    /// list resolved flags, set, and clear tenant/workspace overrides - but only for
    /// flags the operator marked tenant-overridable. In the Admin system-role set and
    /// grantable in a custom role like any non-owner-reserved permission. Not
    /// self-escalation (it toggles rollout state, not authority), so it is grantable
    /// to a service account too.
    /// </summary>
    public const string FeatureFlagsManage = "feature-flags:manage";

    /// <summary>
    /// Export the whole tenant data set (data-export-and-erasure.md section 3, GDPR
    /// Art. 15/20). A bulk export is an administrative act, so it is in the Admin+Owner
    /// system-role set, and it is grantable in a custom role like any non-owner-reserved
    /// permission - but NEVER to a service account
    /// (<see cref="NotServiceAccountGrantable"/>): a bulk-exfiltration primitive on an
    /// unattended, always-on key is exactly what to refuse.
    /// </summary>
    public const string DataExport = "data:export";

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
        AuditRead,
        ApiKeysManage,
        WebhooksManage,
        FeatureFlagsManage,
        DataExport,
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

    /// <summary>
    /// The self-escalation primitives that can never be granted to a
    /// service-account principal (service-accounts.md section 4):
    /// <see cref="RolesManage"/> lets a principal author a custom role from the
    /// whole non-owner-reserved catalogue and assign it to itself, and
    /// <see cref="ApiKeysManage"/> lets it mint further keys. A human admin holding
    /// them is a supervised, interactive actor; a service account is a scriptable,
    /// always-on, unattended credential, so a single leaked or over-scoped key
    /// holding either would be a silent path to near-total tenant compromise.
    /// These stay grantable to a user or team; only a service account is refused
    /// a role whose permission set intersects this set (a service account can
    /// still hold powerful operational permissions like <c>members:manage</c> -
    /// what it cannot do is expand its OWN authority without a human).
    /// </summary>
    public static readonly FrozenSet<string> NotServiceAccountGrantable = new[]
    {
        RolesManage,
        ApiKeysManage,
        // A bulk data export on an unattended, always-on service-account key is a
        // distinct risk class from self-escalation: a single leaked key that can pull
        // the entire tenant data set in one call is exactly what to refuse. So
        // data:export is a human-admin capability only (data-export-and-erasure.md
        // section 3).
        DataExport,
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>True when <paramref name="permission"/> is a catalogue permission.</summary>
    public static bool IsKnown(string permission) => All.Contains(permission);

    /// <summary>True when <paramref name="permission"/> is owner-reserved (never in a custom role).</summary>
    public static bool IsOwnerReserved(string permission) => OwnerReserved.Contains(permission);

    /// <summary>
    /// True when <paramref name="permission"/> is a self-escalation primitive that
    /// must not be granted to a service-account principal
    /// (<see cref="NotServiceAccountGrantable"/>).
    /// </summary>
    public static bool IsNotServiceAccountGrantable(string permission) =>
        NotServiceAccountGrantable.Contains(permission);
}
