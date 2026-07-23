using Starter.Platform.Auth;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.memberships row: one user's membership of one tenant, with a role.
/// Tenant-owned in the ordinary way (a real tenant_id column, the RLS
/// discriminator and the query-filter key). Unique on (tenant_id, user_id): a
/// user belongs to a tenant at most once. user_id and invited_by are bare uuid
/// columns referencing identity users by value only - no cross-schema FK
/// (modular-monolith schema-per-module convention).
/// </summary>
internal sealed class Membership : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    public required Guid UserId { get; init; }

    /// <summary>One of owner | admin | member (stored as a string).</summary>
    public required string Role { get; set; }

    /// <summary>One of active | suspended (stored as a string).</summary>
    public required string Status { get; set; }

    /// <summary>The user who invited this member, or null for a self-serve owner.</summary>
    public Guid? InvitedBy { get; init; }

    /// <summary>
    /// The IdP's SCIM <c>externalId</c> for this member, or null when the membership
    /// was not directory-provisioned (sso-and-scim.md section 5). It rounds a SCIM
    /// client's stable per-user handle back on GET/PUT so reconciliation lines up.
    /// Per-(tenant, user), so it belongs on the membership, not the global user. Not
    /// a secret - included in the membership DSAR export like the other columns.
    /// </summary>
    public string? ScimExternalId { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>tenancy.memberships.role values (the schema owns the full set).</summary>
internal static class MembershipRole
{
    public const string Owner = "owner";

    public const string Admin = "admin";

    public const string Member = "member";
}

/// <summary>
/// Maps between the stored role strings and the platform's ranked
/// <see cref="TenantRole"/>. The storage strings are the schema's source of
/// truth (owner | admin | member); the enum is the shared surface a capability
/// check compares against. Keeping the map in one place means the rank order
/// (owner &gt; admin &gt; member) and the string spellings never drift.
/// </summary>
internal static class MembershipRoles
{
    /// <summary>The ranked role for a stored string, or null for an unknown value.</summary>
    public static TenantRole? ToTenantRole(string role) => role switch
    {
        MembershipRole.Owner => TenantRole.Owner,
        MembershipRole.Admin => TenantRole.Admin,
        MembershipRole.Member => TenantRole.Member,
        _ => null,
    };

    /// <summary>
    /// True for a role an admin may assign or invite (admin | member). Owner is
    /// excluded on purpose: ownership moves through transfer-ownership only.
    /// </summary>
    public static bool IsAssignable(string role) =>
        role is MembershipRole.Admin or MembershipRole.Member;
}

/// <summary>tenancy.memberships.status values.</summary>
internal static class MembershipStatus
{
    public const string Active = "active";

    public const string Suspended = "suspended";
}
