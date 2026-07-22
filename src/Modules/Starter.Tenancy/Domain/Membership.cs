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

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>tenancy.memberships.role values (the schema owns the full set).</summary>
internal static class MembershipRole
{
    public const string Owner = "owner";

    public const string Admin = "admin";

    public const string Member = "member";
}

/// <summary>tenancy.memberships.status values.</summary>
internal static class MembershipStatus
{
    public const string Active = "active";

    public const string Suspended = "suspended";
}
