using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.team_members row: one user's membership of one team (multi-tenancy.md
/// sections 14, 17). Tenant-owned in the ordinary way (a real tenant_id column,
/// the RLS discriminator and the query-filter key). Unique on (team_id, user_id):
/// a user belongs to a team at most once. user_id is a bare uuid referencing an
/// identity user by value only - no cross-schema FK (schema-per-module
/// convention); team_id carries an intra-schema FK to <see cref="Team"/> that
/// cascades on team delete, so a team's memberships vanish with it.
/// </summary>
internal sealed class TeamMember : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>The team the user belongs to. FK team_id -> teams(id), cascade on delete.</summary>
    public required Guid TeamId { get; init; }

    /// <summary>The member's user id. A bare id by value, no cross-schema FK.</summary>
    public required Guid UserId { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
