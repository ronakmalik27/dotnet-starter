using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The only public surface of the Tenancy module. Owns tenants, memberships,
/// invitations, and the control-plane operations over them. Starter.Api composes
/// the HTTP endpoints over these commands (modules never self-host routes).
/// Signatures use primitives and platform contract types only, so the module
/// exports no other public type (ModuleSurfaceTests).
/// <para>
/// It inherits <see cref="ITenantRoleReader"/> so the RequireTenantRole endpoint
/// gate can read the caller's active-tenant role through the module facade; the
/// same lookup backs the platform's layer-3 resource handler, bridged by the
/// composition root, so there is one implementation and no drift.
/// </para>
/// </summary>
public interface ITenancyApi : ITenantRoleReader
{
    /// <summary>
    /// Self-serve signup: creates a brand-new user, a new tenant, and the
    /// caller's owner membership ATOMICALLY in one transaction on the bypass
    /// data source, then (post-commit, best-effort) sends the verification email
    /// and logs the new owner in bound to the new tenant. Success carries the
    /// auto-login tokens on the fresh path (the access token's tid is the new
    /// tenant); it carries no tokens when the email already had an account - the
    /// enumeration-safe generic success that creates nothing and does not leak
    /// that the address pre-existed. A slug already taken is a Conflict
    /// (tenancy.slug_taken); a bad email or weak password is a Validation
    /// failure. "A failure leaves neither a user nor a tenant" is a tested
    /// invariant - every write shares one transaction.
    /// </summary>
    Task<Result<SelfServeSignup>> ProvisionSelfServeAsync(
        string email,
        string password,
        string tenantName,
        string slug,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// True when <paramref name="userId"/> is an active member of
    /// <paramref name="tenantId"/>. The tenant-token mint gate: it runs on the
    /// bypass path because the caller holds no tid for the tenant yet, so an
    /// RLS-bound lookup keyed on the current-tenant GUC would see nothing. A
    /// non-member (or an absent tenant) is false, so the endpoint answers 404
    /// and never confirms the tenant exists.
    /// </summary>
    Task<bool> IsActiveMemberAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// True when the tenant exists and is active. The tenant-token mint reads it
    /// (after the membership check) to refuse minting a new tid token for a
    /// suspended or deleted tenant (multi-tenancy.md section 6 lifecycle);
    /// existing tid tokens age out within the 15-minute access window. On the
    /// bypass path (the caller holds no tid yet). A missing tenant is false.
    /// </summary>
    Task<bool> IsTenantActiveAsync(Guid tenantId, CancellationToken cancellationToken);

    // --- Platform super-admin plane (cross-tenant, bypass path) -----------
    // Every command below is platform-plane control-plane work on the bypass
    // data source (multi-tenancy.md section 7), gated by RequirePlatformAdmin at
    // the endpoint (platform.platform_admins membership, never a tenant role).

    /// <summary>
    /// True when <paramref name="userId"/> is a platform super-admin (a
    /// platform.platform_admins row). Backs the RequirePlatformAdmin gate.
    /// Platform power is never a tenant role.
    /// </summary>
    Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Lists (and optionally searches by slug or name) tenants across every
    /// tenant, bounded by <paramref name="limit"/>. A cross-tenant read on the
    /// bypass path.
    /// </summary>
    Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)>>
        ListTenantsAsync(string? query, int limit, CancellationToken cancellationToken);

    /// <summary>Views one tenant by id, or null when it does not exist. Cross-tenant read on the bypass path.</summary>
    Task<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)?>
        GetTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Suspends a tenant (active -> suspended); emits TenantSuspended. Not-active is a Conflict.</summary>
    Task<Result> SuspendTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Reactivates a suspended tenant (suspended -> active); emits TenantReactivated. Not-suspended is a Conflict.</summary>
    Task<Result> ReactivateTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Soft-deletes a tenant (status -> deleted) on the platform plane; emits TenantSoftDeleted. Already-deleted is a Conflict.</summary>
    Task<Result> PlatformDeleteTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Lists the platform admins: user id, granter (null for the bootstrap seed), granted-at.</summary>
    Task<IReadOnlyList<(Guid UserId, Guid? GrantedBy, DateTimeOffset GrantedAt)>>
        ListPlatformAdminsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Grants platform-admin to a user named by id or email (at least one
    /// required); emits PlatformAdminGranted. Idempotent - an already-admin user
    /// is a benign success. There is no self-grant path (the first admin is
    /// seeded out of band). A user that does not exist is a NotFound.
    /// </summary>
    Task<Result> GrantPlatformAdminAsync(
        Guid actorUserId, Guid? targetUserId, string? email, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes a user's platform-admin; emits PlatformAdminRevoked. Refuses
    /// revoking the LAST platform admin (a Conflict, the lockout guard). A user
    /// who is not an admin is a NotFound.
    /// </summary>
    Task<Result> RevokePlatformAdminAsync(Guid actorUserId, Guid targetUserId, CancellationToken cancellationToken);

    /// <summary>
    /// Starts an impersonation session (multi-tenancy.md section 7): in one
    /// transaction writes the grant row and emits ImpersonationStarted, so no
    /// impersonation token can exist without its audit row. Returns the grant id,
    /// the subject to mint the token as (the target user, or the acting admin
    /// when no target user), the target tenant, and the absolute expiry
    /// (min of the configured window and the 15-minute access cap). The tenant
    /// must exist (any status - a suspended tenant is a valid support target); a
    /// named target user must be a real active account; a blank reason is a
    /// Validation failure.
    /// </summary>
    Task<Result<(Guid GrantId, Guid SubjectUserId, Guid TargetTenantId, DateTimeOffset ExpiresAt)>>
        StartImpersonationAsync(
            Guid actorUserId, Guid tenantId, Guid? targetUserId, string reason, CancellationToken cancellationToken);

    /// <summary>
    /// Ends an impersonation session: sets ended_at and emits ImpersonationEnded.
    /// Idempotent - a grant already ended is a benign no-op success; an unknown
    /// grant is a NotFound. The per-request guard makes the effect immediate.
    /// </summary>
    Task<Result> EndImpersonationAsync(Guid actorUserId, Guid grantId, CancellationToken cancellationToken);

    // --- Tenant-admin control plane (active tenant, request path under RLS) ---
    // Every command below operates on the ACTIVE tenant resolved from the tid
    // claim; the endpoint gates each with RequireTenant + RequireTenantRole
    // (admin+, owner-only where noted) before it runs. GetCallerRoleAsync (the
    // gate's own read) is inherited from ITenantRoleReader.

    /// <summary>Lists the active tenant's members (member+): user id, role, status, created-at.</summary>
    Task<IReadOnlyList<(Guid UserId, string Role, string Status, DateTimeOffset CreatedAt)>>
        ListMembersAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Changes a member's role to admin or member (admin+). Refuses promoting to
    /// owner (that is transfer-ownership), changing your own role, targeting a
    /// non-member, and demoting the last owner.
    /// </summary>
    Task<Result> ChangeMemberRoleAsync(
        Guid callerUserId, Guid targetUserId, string role, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a member (admin+, hard delete - audit lives on the event spine).
    /// Refuses removing the last owner; a member or admin may remove themselves.
    /// </summary>
    Task<Result> RemoveMemberAsync(Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken);

    /// <summary>
    /// Invites an email (admin+) with an admin|member role: creates a hashed,
    /// single-use, expiring invitation and emails the link. Refuses inviting an
    /// address that is already an active member or already has a pending invite.
    /// Returns the new invitation id.
    /// </summary>
    Task<Result<Guid>> InviteMemberAsync(
        Guid callerUserId, string email, string role, CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's pending (unaccepted, unexpired) invitations (admin+).</summary>
    Task<IReadOnlyList<(Guid Id, string Email, string Role, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt)>>
        ListInvitationsAsync(CancellationToken cancellationToken);

    /// <summary>Revokes a pending invitation by id (admin+). Unknown/accepted is a NotFound.</summary>
    Task<Result> RevokeInvitationAsync(Guid callerUserId, Guid invitationId, CancellationToken cancellationToken);

    /// <summary>
    /// Updates the active tenant's name and/or slug (admin+). A slug collision on
    /// the citext unique index is a Conflict (tenancy.slug_taken).
    /// </summary>
    Task<Result> UpdateSettingsAsync(
        Guid callerUserId, string? name, string? slug, CancellationToken cancellationToken);

    /// <summary>
    /// Transfers ownership to an existing active member (owner-only): the target
    /// becomes owner and the caller steps down to admin, in one transaction.
    /// </summary>
    Task<Result> TransferOwnershipAsync(
        Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken);

    /// <summary>Soft-deletes the active tenant (owner-only): status -> deleted, never a hard row delete.</summary>
    Task<Result> SoftDeleteTenantAsync(Guid callerUserId, CancellationToken cancellationToken);

    /// <summary>The active tenant's seat limit and current active-member count (member+).</summary>
    Task<(int SeatLimit, int ActiveMembers)> GetSeatsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Accepts an invitation (its own flow, NOT tenant-admin): the authenticated
    /// caller redeems the raw token on the bypass path. Validates the token
    /// (exists, unaccepted, unexpired, addressed to the caller's email), enforces
    /// the seat limit under a tenant row lock, creates the active membership,
    /// consumes the token, and emits MembershipCreated - all in one transaction.
    /// Success carries the joined tenant id and the granted role so the caller
    /// can then mint a tid token. A seat-limit hit is a Conflict
    /// (tenancy.seat_limit_reached); every validation miss is one generic
    /// NotFound (tenancy.invitation_invalid).
    /// </summary>
    Task<Result<(Guid TenantId, string Role)>> AcceptInvitationAsync(
        Guid userId, string token, CancellationToken cancellationToken);
}
