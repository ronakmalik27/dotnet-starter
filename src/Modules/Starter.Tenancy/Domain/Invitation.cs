using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.invitations row: a pending offer for an email to join a tenant with
/// a role. Tenant-owned in the ordinary way (a real tenant_id column, the RLS
/// discriminator and the query-filter key). The raw invite token reaches the
/// invitee only through the emailed link - the row stores only its SHA-256 hex
/// digest, the same pattern as identity's one_time_tokens - and the accept flow
/// reads by <see cref="TokenHash"/> on the bypass path, since the invitee is not
/// yet a member and holds no tid for this tenant. Single-use is enforced by
/// <see cref="AcceptedAt"/> (set once at consumption); expiry by
/// <see cref="ExpiresAt"/>. Only admin | member is ever invited: ownership is
/// transferred, never invited.
/// <para>
/// A scope-aware invitation (multi-tenancy.md section 16) also carries a
/// <see cref="WorkspaceId"/> and a <see cref="RoleId"/> (a custom role): on
/// accept, the matching workspace-scoped role_assignment is created in the same
/// bypass transaction as the membership. Both are null for a plain tenant invite;
/// they are set together for "invited straight into a role on a workspace".
/// </para>
/// </summary>
internal sealed class Invitation : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>The invited address (citext, case-insensitive).</summary>
    public required string Email { get; init; }

    /// <summary>One of admin | member (never owner).</summary>
    public required string Role { get; init; }

    /// <summary>SHA-256 of the 256-bit random token, lowercase hex.</summary>
    public required string TokenHash { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set exactly once when the invitation is consumed; never cleared.</summary>
    public DateTimeOffset? AcceptedAt { get; set; }

    /// <summary>
    /// The workspace a scope-aware invite grants a role in (section 16), or null
    /// for a plain tenant invite. Set together with <see cref="RoleId"/>.
    /// </summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>
    /// The custom role to grant at <see cref="WorkspaceId"/> on accept, or null
    /// for a plain tenant invite. Validated at invite time (the role exists, is
    /// assignable at workspace scope, and a workspace-local role owns that same
    /// workspace); set together with <see cref="WorkspaceId"/>.
    /// </summary>
    public Guid? RoleId { get; init; }

    /// <summary>The admin who created the invitation. A bare id by value, no cross-schema FK.</summary>
    public required Guid InvitedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
