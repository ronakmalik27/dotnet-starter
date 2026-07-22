using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.teams row: a named group of users INSIDE one tenant that can hold
/// grants, so access is managed for a group instead of user by user (GitHub
/// teams; multi-tenancy.md sections 14, 17). Tenant-owned in the ordinary way (a
/// real tenant_id column, the RLS discriminator and the query-filter key), so
/// listing teams is an ordinary tenant-scoped read and one tenant can never see
/// another's teams.
/// <para>
/// A team is a principal in <see cref="RoleAssignment"/> (principal_type = team):
/// the effective-permission resolver unions the grants of every team the caller
/// belongs to (section 13). Slug is unique per tenant (citext), mirroring
/// tenancy.tenants and tenancy.workspaces.
/// </para>
/// </summary>
internal sealed class Team : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>Case-insensitive unique per tenant (citext), caller-supplied at create.</summary>
    public required string Slug { get; init; }

    /// <summary>The human-facing name. Editable.</summary>
    public required string Name { get; set; }

    /// <summary>The user who created the team. A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
