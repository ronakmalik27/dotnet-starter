using Starter.Platform.Auth;
using Starter.Platform.Dsar;
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
/// gate can read the caller's active-tenant role through the module facade, and
/// <see cref="IPermissionResolver"/> so the RequirePermission gate can read the
/// caller's effective permission set the same way; both lookups also back
/// platform seams bridged by the composition root, so there is one
/// implementation of each and no drift.
/// </para>
/// </summary>
public interface ITenancyApi : ITenantRoleReader, IPermissionResolver
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

    /// <summary>Soft-deletes a tenant (status -> deleted) on the platform plane; emits TenantSoftDeleted, stamps deleted_at. Already-deleted is a Conflict.</summary>
    Task<Result> PlatformDeleteTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Hard-deletes (erases) a tenant on the platform plane (data-export-and-erasure.md
    /// section 5, GDPR Art. 17): in ONE bypass transaction, locks the tenant row,
    /// requires <c>status = deleted</c> (else a Conflict, <c>platform.tenant_state</c>)
    /// and either the retention window elapsed or <paramref name="force"/> (else a
    /// Conflict, <c>platform.retention_not_elapsed</c>), captures the redacted pre-purge
    /// snapshot, purges every declared tenant-owned table plus the session revoke, and
    /// records <c>platform.tenant.erased</c> on the surviving platform audit log. A
    /// missing (or already-erased) tenant is a NotFound. Returns the operator snapshot.
    /// </summary>
    Task<Result<TenantErasureSnapshot>> EraseTenantAsync(
        Guid actorUserId, Guid tenantId, bool force, CancellationToken cancellationToken);

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

    // --- Plan catalogue (operator-owned, bypass path) ---------------------
    // The plan catalogue (billing-and-entitlements.md sections 2, 7) is global
    // operator vocabulary, edited only on the bypass path behind
    // RequirePlatformAdmin. features / permissions are null = unrestricted.

    /// <summary>Lists the plan catalogue: key, name, features (null = unrestricted), permissions (null = unrestricted), limits, default flag, timestamps.</summary>
    Task<IReadOnlyList<(string Key, string Name, IReadOnlyList<string>? Features, IReadOnlyList<string>? Permissions, IReadOnlyDictionary<string, int> Limits, bool IsDefault, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListPlansAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Creates a plan-catalogue entry; audited synchronously on the platform audit
    /// log. <paramref name="features"/> / <paramref name="permissions"/> null means
    /// unrestricted (SQL NULL); <paramref name="limits"/> MUST declare a positive
    /// seatLimit (Validation otherwise). A duplicate key is a Conflict. When
    /// <paramref name="isDefault"/> is true the current default is demoted in the
    /// same transaction (exactly-one-default).
    /// </summary>
    Task<Result> CreatePlanAsync(
        Guid actorUserId,
        string key,
        string name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool isDefault,
        CancellationToken cancellationToken);

    /// <summary>
    /// Updates a plan-catalogue entry (PATCH semantics: a null argument leaves that
    /// facet unchanged; a supplied array replaces). A supplied
    /// <paramref name="limits"/> must still declare a positive seatLimit. Promoting
    /// <paramref name="isDefault"/> to true demotes the current default in one
    /// transaction. An unknown key is a NotFound. Audited synchronously.
    /// </summary>
    Task<Result> UpdatePlanAsync(
        Guid actorUserId,
        string key,
        string? name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool? isDefault,
        CancellationToken cancellationToken);

    /// <summary>
    /// Assigns a plan to a tenant (billing-and-entitlements.md section 7): sets
    /// <c>tenant.plan</c> and denormalizes the plan's seatLimit onto
    /// <c>tenant.seat_limit</c>, emitting tenancy.tenant.plan_changed with the old
    /// and new keys. The plan must exist (a NotFound otherwise), so a tenant is
    /// never assigned a dangling key; a missing tenant is a NotFound. This is the
    /// single seam a payment-provider callback drives after a real payment
    /// (section 9).
    /// </summary>
    Task<Result> AssignPlanAsync(
        Guid actorUserId, Guid tenantId, string planKey, CancellationToken cancellationToken);

    // --- Feature-flag catalogue (operator-owned, bypass path) --------------
    // The feature-flag catalogue (feature-flags.md sections 2, 5) is global operator
    // vocabulary, edited only on the bypass path behind RequirePlatformAdmin. Flags
    // fail CLOSED, so the catalogue seeds empty. Tenant-scoped override management is
    // a separate request-path surface (IFeatureFlagAdmin), gated by feature-flags:manage.

    /// <summary>Lists the feature-flag catalogue: key, description, default, rollout (null = no rollout), overridable, archived, timestamps.</summary>
    Task<IReadOnlyList<(string Key, string Description, bool DefaultEnabled, int? RolloutPercentage, bool TenantOverridable, bool Archived, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListFeatureFlagsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Creates a feature-flag catalogue entry; audited synchronously on the platform
    /// audit log. <paramref name="rolloutPercentage"/> null means no rollout (use
    /// <paramref name="defaultEnabled"/>); a value must be 0..100. A duplicate key is
    /// a Conflict.
    /// </summary>
    Task<Result> CreateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string description,
        bool defaultEnabled,
        int? rolloutPercentage,
        bool tenantOverridable,
        CancellationToken cancellationToken);

    /// <summary>
    /// Updates a feature-flag catalogue entry (PATCH semantics: a null argument
    /// leaves that facet unchanged). <paramref name="archived"/> true archives (the
    /// flag then resolves OFF and is hidden), false unarchives, null leaves it. An
    /// unknown key is a NotFound. Audited synchronously.
    /// </summary>
    Task<Result> UpdateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string? description,
        bool? defaultEnabled,
        int? rolloutPercentage,
        bool? tenantOverridable,
        bool? archived,
        CancellationToken cancellationToken);

    // --- Role-template catalogue (operator-owned, bypass path) -------------
    // The role-template catalogue (role-templates-and-policy-defaults.md section 2)
    // is global operator vocabulary, edited only on the bypass path behind
    // RequirePlatformAdmin. A template is SEEDED into a tenant as one of its OWN
    // custom roles (the tenant then owns the copy); editing a template does not
    // retro-change already-seeded copies. permissions and assignableScopes are exact
    // sets, never "unrestricted".

    /// <summary>Lists the role-template catalogue: key, name, description, permissions, assignable scopes, timestamps.</summary>
    Task<IReadOnlyList<(string Key, string Name, string Description, IReadOnlyList<string> Permissions, IReadOnlyList<string> AssignableScopes, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListRoleTemplatesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Creates a role-template catalogue entry; audited synchronously on the platform
    /// audit log. Every permission must be a real catalogue atom and none
    /// owner-reserved (Validation otherwise); <paramref name="assignableScopes"/> must
    /// be a non-empty subset of {tenant, workspace}. A duplicate key is a Conflict.
    /// </summary>
    Task<Result> CreateRoleTemplateAsync(
        Guid actorUserId,
        string key,
        string name,
        string description,
        IReadOnlyList<string> permissions,
        IReadOnlyList<string> assignableScopes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Updates a role-template catalogue entry (PATCH semantics: a null argument
    /// leaves that facet unchanged; a supplied array replaces, validated like create).
    /// An unknown key is a NotFound. Audited synchronously. Does NOT retro-change
    /// already-seeded tenant copies.
    /// </summary>
    Task<Result> UpdateRoleTemplateAsync(
        Guid actorUserId,
        string key,
        string? name,
        string? description,
        IReadOnlyList<string>? permissions,
        IReadOnlyList<string>? assignableScopes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes a role-template catalogue entry; audited synchronously. An unknown key
    /// is a NotFound. Already-seeded tenant copies are the tenants' own roles and are
    /// untouched.
    /// </summary>
    Task<Result> DeleteRoleTemplateAsync(Guid actorUserId, string key, CancellationToken cancellationToken);

    /// <summary>
    /// Seeds one role template into every tenant (or the single
    /// <paramref name="tenantId"/> when given) as an ordinary tenant custom role,
    /// idempotently via the template_key guard (a tenant already carrying it is
    /// skipped). Permissions are filtered to each tenant's plan-allowed subset (skip
    /// disallowed, never escalate). Returns the number of tenants newly seeded. A
    /// missing template - or a named tenant that does not exist - is a NotFound.
    /// </summary>
    Task<Result<int>> SeedRoleTemplateAsync(
        Guid actorUserId, string key, Guid? tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the install-wide policy-defaults singleton (super-admin,
    /// role-templates-and-policy-defaults.md section 3): the password, session, and
    /// lockout floors the whole install inherits. Falls back to the built-in
    /// constants when the singleton row is somehow absent.
    /// </summary>
    Task<(int PasswordMinLength, int AccessTokenLifetimeSeconds, int RefreshLifetimeSeconds, int LockoutMaxAttempts, int LockoutDurationSeconds)>
        GetPolicyDefaultsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Updates the policy-defaults singleton (super-admin). Each field is a PATCH
    /// tri-state: a null argument leaves that facet unchanged, a value replaces it.
    /// Values are bounds-validated (positive, sane maxima). Audited synchronously as
    /// <c>platform.policy.updated</c> and the in-process reader cache is invalidated,
    /// so a change lands on the very next login-path read.
    /// </summary>
    Task<Result> UpdatePolicyDefaultsAsync(
        Guid actorUserId,
        int? passwordMinLength,
        int? accessTokenLifetimeSeconds,
        int? refreshLifetimeSeconds,
        int? lockoutMaxAttempts,
        int? lockoutDurationSeconds,
        CancellationToken cancellationToken);

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
    /// Invites an email (admin+) with an admin|member base role: creates a hashed,
    /// single-use, expiring invitation and emails the link. Refuses inviting an
    /// address that is already an active member or already has a pending invite.
    /// A scope-aware invite (multi-tenancy.md section 16) also passes a
    /// <paramref name="workspaceId"/> + <paramref name="roleId"/> (both together,
    /// or both null): the custom role to grant at that workspace on accept,
    /// validated at invite time (the role exists, is assignable at workspace
    /// scope, and a workspace-local role owns that workspace). Returns the new
    /// invitation id.
    /// </summary>
    Task<Result<Guid>> InviteMemberAsync(
        Guid callerUserId,
        string email,
        string role,
        Guid? workspaceId,
        Guid? roleId,
        CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's pending (unaccepted, unexpired) invitations (admin+).</summary>
    Task<IReadOnlyList<(Guid Id, string Email, string Role, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt)>>
        ListInvitationsAsync(CancellationToken cancellationToken);

    /// <summary>Revokes a pending invitation by id (admin+). Unknown/accepted is a NotFound.</summary>
    Task<Result> RevokeInvitationAsync(Guid callerUserId, Guid invitationId, CancellationToken cancellationToken);

    /// <summary>
    /// Updates the active tenant's name, slug, and/or session-lifetime override
    /// (admin+, settings:manage). A slug collision on the citext unique index is a
    /// Conflict (tenancy.slug_taken). <paramref name="sessionMaxSeconds"/>, when
    /// given, is the tenant's tid-token lifetime override
    /// (role-templates-and-policy-defaults.md section 5): validated positive and no
    /// longer than the platform access-token lifetime (tighten only; a longer value
    /// is rejected). Null leaves the current override unchanged.
    /// </summary>
    Task<Result> UpdateSettingsAsync(
        Guid callerUserId, string? name, string? slug, int? sessionMaxSeconds, CancellationToken cancellationToken);

    /// <summary>
    /// Transfers ownership to an existing active member (owner-only): the target
    /// becomes owner and the caller steps down to admin, in one transaction.
    /// </summary>
    Task<Result> TransferOwnershipAsync(
        Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken);

    /// <summary>Soft-deletes the active tenant (owner-only): status -> deleted, stamps deleted_at, never a hard row delete.</summary>
    Task<Result> SoftDeleteTenantAsync(Guid callerUserId, CancellationToken cancellationToken);

    /// <summary>
    /// Records a completed self-serve data export on the active tenant's spine
    /// (data-export-and-erasure.md section 6): emits <c>tenancy.tenant.data_exported</c>
    /// (tenant-scoped, audited, webhook-deliverable) with the per-section row-count
    /// <paramref name="sectionCounts"/> summary and no data copy. The bundle itself is
    /// assembled by the platform export service; this is the audit trail.
    /// </summary>
    Task<Result> RecordDataExportAsync(
        Guid callerUserId, IReadOnlyDictionary<string, int> sectionCounts, CancellationToken cancellationToken);

    /// <summary>
    /// The active tenant's seat limit and current active-member count (member+),
    /// plus its assigned plan and that plan's declared numeric limits
    /// (billing-and-entitlements.md sections 5, 7). The seat limit is
    /// plan-derived (assign-plan denormalizes it onto the tenant row).
    /// </summary>
    Task<(int SeatLimit, int ActiveMembers, string? Plan, IReadOnlyDictionary<string, int> Limits)>
        GetSeatsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// The active tenant's resolved commercial entitlements
    /// (billing-and-entitlements.md section 3): reads the tenant's plan under RLS
    /// (the GetSeatsAsync pattern) then resolves it via the platform entitlement
    /// source. A null / unknown plan resolves to unrestricted (fail open). Backs
    /// the RequireEntitlement endpoint filter.
    /// </summary>
    Task<Entitlements> GetCallerEntitlementsAsync(CancellationToken cancellationToken);

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

    // --- Workspaces (active tenant, request path under RLS) ---------------
    // A workspace is a scope INSIDE the tenant (multi-tenancy.md section 12),
    // tenant-owned under RLS. Workspace CRUD is gated at TENANT scope
    // (RequirePermission workspaces:read / workspaces:manage); the workspace-
    // scoped RBAC and resource operations below are gated at WORKSPACE scope.

    /// <summary>
    /// True when <paramref name="workspaceId"/> is visible under the active
    /// tenant's RLS (multi-tenancy.md section 12). Backs the RequireWorkspace
    /// gate: a cross-tenant workspace is invisible and reads as false, so the gate
    /// answers 404 rather than confirming it exists elsewhere.
    /// </summary>
    Task<bool> WorkspaceExistsAsync(Guid workspaceId, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a workspace (workspaces:manage). Validates the slug and name and
    /// refuses a duplicate slug within the tenant (Conflict
    /// tenancy.workspace_slug_taken). Returns the new workspace id.
    /// </summary>
    Task<Result<Guid>> CreateWorkspaceAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's workspaces (workspaces:read): id, slug, name, status, created-at.</summary>
    Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        ListWorkspacesAsync(CancellationToken cancellationToken);

    /// <summary>Gets one workspace (workspaces:read). Unknown id is a NotFound (tenancy.workspace_not_found).</summary>
    Task<Result<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        GetWorkspaceAsync(Guid workspaceId, CancellationToken cancellationToken);

    /// <summary>Renames a workspace (workspaces:manage). Unknown id is a NotFound.</summary>
    Task<Result> RenameWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Archives a workspace (workspaces:manage): active -> archived, reversible,
    /// nothing destroyed (section 20). Its resources become read-only (mutating
    /// workspace-scoped routes 409). Idempotent - an already-archived workspace is
    /// a benign success. Unknown id is a NotFound.
    /// </summary>
    Task<Result> ArchiveWorkspaceAsync(Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken);

    /// <summary>
    /// Unarchives a workspace (workspaces:manage): archived -> active, so its
    /// resources are writable again (section 20 - archive is reversible).
    /// Idempotent - an already-active workspace is a benign success. Unknown id is
    /// a NotFound.
    /// </summary>
    Task<Result> UnarchiveWorkspaceAsync(Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken);

    // --- Custom roles and assignments (active tenant, request path under RLS) ---
    // The scoped-RBAC control plane (multi-tenancy.md sections 13, 15). Every
    // command below operates on the ACTIVE tenant. Tenant-scope operations are
    // gated by RequirePermission("roles:manage"); workspace-scope operations by
    // RequireWorkspace + the workspace-scoped RequirePermission("roles:manage").
    // GetCallerPermissionsAsync (the gate's own read) is inherited from
    // IPermissionResolver, at tenant and at workspace scope.

    /// <summary>
    /// Creates a custom role from a subset of the permission catalogue (roles:manage).
    /// A null <paramref name="workspaceId"/> creates a tenant-owned role; a set value
    /// creates a WORKSPACE-LOCAL role in that workspace (assignableAt must be
    /// "workspace", the workspace must exist). Refuses an unknown or owner-reserved
    /// permission (Validation) and a duplicate (tenant, workspace_id, key) (Conflict
    /// tenancy.role_key_taken). Returns the new role id. <paramref name="assignableAt"/>
    /// is tenant | workspace | both.
    /// </summary>
    Task<Result<Guid>> CreateRoleAsync(
        Guid callerUserId,
        string key,
        string name,
        string? description,
        string assignableAt,
        Guid? workspaceId,
        IReadOnlyCollection<string> permissions,
        CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's tenant-owned custom roles (roles:manage): id, key, name, description, assignableAt, created-at.</summary>
    Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListRolesAsync(CancellationToken cancellationToken);

    /// <summary>Lists a workspace's workspace-local custom roles (roles:manage at that workspace).</summary>
    Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListWorkspaceRolesAsync(Guid workspaceId, CancellationToken cancellationToken);

    /// <summary>Gets one custom role and its permissions (roles:manage). Unknown id is a NotFound (tenancy.role_not_found).</summary>
    Task<Result<(Guid Id, string Key, string Name, string? Description, string AssignableAt, IReadOnlyList<string> Permissions, DateTimeOffset CreatedAt)>>
        GetRoleAsync(Guid roleId, CancellationToken cancellationToken);

    /// <summary>
    /// Updates a custom role's name, description, and/or permission set (roles:manage).
    /// A null argument leaves that facet unchanged; a supplied permission set
    /// replaces the role's permissions wholesale (validated like create). The
    /// change takes effect for every holder on their next request.
    /// </summary>
    Task<Result> UpdateRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string? name,
        string? description,
        IReadOnlyCollection<string>? permissions,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes a custom role (roles:manage). Refuses deleting a role that has
    /// assignments (Conflict tenancy.role_in_use): its grants must be revoked or
    /// reassigned first, so access never dangles.
    /// </summary>
    Task<Result> DeleteRoleAsync(Guid callerUserId, Guid roleId, CancellationToken cancellationToken);

    /// <summary>
    /// Assigns a custom role to a principal at a scope (roles:manage at that
    /// scope). <paramref name="principalType"/> is user | team and
    /// <paramref name="principalId"/> is the user or team id (multi-tenancy.md
    /// sections 13, 14). <paramref name="scopeType"/> is tenant | workspace;
    /// <paramref name="scopeId"/> is null for tenant scope, else the workspace id.
    /// Validates that the role's assignable_at allows the scope, that a
    /// workspace-local role is assigned only at its own workspace (else Validation
    /// tenancy.workspace_role_scope), that a named workspace exists, and that the
    /// principal exists in this tenant (a user principal is an active member; a
    /// team principal is a real team). Returns the new assignment id. A duplicate
    /// grant at the same scope is a Conflict.
    /// </summary>
    Task<Result<Guid>> AssignRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string principalType,
        Guid principalId,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken);

    /// <summary>Revokes a role assignment by id (roles:manage). Unknown id is a NotFound.</summary>
    Task<Result> RevokeAssignmentAsync(Guid callerUserId, Guid assignmentId, CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's role assignments across all scopes (roles:manage).</summary>
    Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, DateTimeOffset CreatedAt)>>
        ListAssignmentsAsync(CancellationToken cancellationToken);

    /// <summary>Lists a workspace's role assignments (roles:manage at that workspace).</summary>
    Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, DateTimeOffset CreatedAt)>>
        ListWorkspaceAssignmentsAsync(Guid workspaceId, CancellationToken cancellationToken);

    // --- Teams (active tenant, request path under RLS) --------------------
    // A team is a named group of users INSIDE the tenant that can hold grants
    // (multi-tenancy.md sections 14, 20), tenant-owned under RLS. Every command
    // below operates on the ACTIVE tenant and is gated by
    // RequirePermission("teams:manage"). A role is granted TO a team through the
    // assignment API above (principalType = team).

    /// <summary>
    /// Creates a team (teams:manage). Validates the slug and name and refuses a
    /// duplicate slug within the tenant (Conflict tenancy.team_slug_taken).
    /// Returns the new team id.
    /// </summary>
    Task<Result<Guid>> CreateTeamAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken);

    /// <summary>Lists the active tenant's teams (teams:manage): id, slug, name, created-at.</summary>
    Task<IReadOnlyList<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        ListTeamsAsync(CancellationToken cancellationToken);

    /// <summary>Gets one team (teams:manage). Unknown id is a NotFound (tenancy.team_not_found).</summary>
    Task<Result<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        GetTeamAsync(Guid teamId, CancellationToken cancellationToken);

    /// <summary>Renames a team (teams:manage). Unknown id is a NotFound.</summary>
    Task<Result> RenameTeamAsync(
        Guid callerUserId, Guid teamId, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes a team (teams:manage). Removes the team's role_assignments first so
    /// no grant dangles (multi-tenancy.md section 20); its team_members cascade
    /// via the FK. Unknown id is a NotFound. A member who held a permission only
    /// through this team loses it on their next request.
    /// </summary>
    Task<Result> DeleteTeamAsync(Guid callerUserId, Guid teamId, CancellationToken cancellationToken);

    /// <summary>
    /// Adds a user to a team (teams:manage). The user must be an active tenant
    /// member (else Validation tenancy.principal_not_member). Refuses a duplicate
    /// (Conflict tenancy.team_member_exists). Returns the new team-member row id.
    /// The team's grants confer to the user on their next request.
    /// </summary>
    Task<Result<Guid>> AddTeamMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a user from a team (teams:manage). Unknown pairing is a NotFound.
    /// The team's grants stop conferring to the user on their next request.
    /// </summary>
    Task<Result> RemoveTeamMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken);

    /// <summary>Lists a team's members (teams:manage): user id, joined-at. Unknown team is a NotFound.</summary>
    Task<Result<IReadOnlyList<(Guid UserId, DateTimeOffset CreatedAt)>>>
        ListTeamMembersAsync(Guid teamId, CancellationToken cancellationToken);

    // --- Service accounts and API keys (service-accounts.md) --------------
    // A service account is a non-human principal that authenticates with a hashed
    // API key and carries scoped RBAC grants, not a membership (section 1). The
    // admin endpoints are on the tenant group, gated by api-keys:manage; the
    // resolve is the authentication path.

    /// <summary>
    /// The caller's effective permissions at TENANT scope for a caller of the
    /// given <paramref name="principalType"/> (service-accounts.md section 4). The
    /// RequirePermission gate reads the caller's principal type from the pt claim
    /// (defaulting to user) and passes it through: a user takes the membership +
    /// system-role + grants path; a service account skips the membership gate and
    /// resolves ONLY its own service-account grants. Cached per request per
    /// (principal, scope, principal type).
    /// </summary>
    Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid principalId, string principalType, CancellationToken cancellationToken);

    /// <summary>The principal-typed overload AT A WORKSPACE; same semantics, plus that workspace's grants.</summary>
    Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid principalId, Guid workspaceId, string principalType, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves a presented API key by its SHA-256 hex hash (service-accounts.md
    /// sections 3, 4): the tenant-less lookup on the bypass path, returning the
    /// (tenant, service-account) pair for a LIVE key or null for every miss -
    /// unknown, revoked, or expired all collapse to null so a holder cannot probe
    /// which keys exist. It also does the throttled last_used_at write. The API-
    /// layer authentication handler calls this after hashing the raw key; the
    /// handler mints sub + tid + pt = service_account on a hit, and 401s on null.
    /// </summary>
    Task<(Guid TenantId, Guid ServiceAccountId)?> ResolveApiKeyAsync(
        string keyHash, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a service account (api-keys:manage) and returns the raw key ONCE
    /// (it is never retrievable again). When <paramref name="roleId"/> is given,
    /// the matching role_assignment is created in the SAME transaction at the
    /// named scope (<paramref name="scopeType"/> tenant | workspace,
    /// <paramref name="scopeId"/> the workspace when workspace-scoped), so the
    /// account lands usable; a self-escalation role (roles:manage / api-keys:manage)
    /// is refused (tenancy.permission_not_automatable) and rolls the whole create
    /// back. An optional <paramref name="expiresAt"/> caps the key's life. An
    /// account created with no role has no permissions until one is assigned.
    /// </summary>
    Task<Result<(Guid Id, string RawKey, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>>
        CreateServiceAccountAsync(
            Guid callerUserId,
            string name,
            DateTimeOffset? expiresAt,
            Guid? roleId,
            string? scopeType,
            Guid? scopeId,
            CancellationToken cancellationToken);

    /// <summary>
    /// Lists the active tenant's service accounts (api-keys:manage), keyset
    /// paginated: id, name, key_prefix, created, last_used, expires, revoked -
    /// NEVER the secret or the hash. A malformed cursor is a Validation failure.
    /// </summary>
    Task<Result<(IReadOnlyList<(Guid Id, string Name, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt)> Items, string? NextCursor)>>
        ListServiceAccountsAsync(int limit, string? cursor, CancellationToken cancellationToken);

    /// <summary>
    /// Rotates a service account's key (api-keys:manage): mints a new secret,
    /// replaces the hash and prefix, and returns the new raw key ONCE. The old
    /// secret stops working immediately (one active hash). Unknown id is a
    /// NotFound (tenancy.service_account_not_found).
    /// </summary>
    Task<Result<(string RawKey, string KeyPrefix)>>
        RotateServiceAccountAsync(Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes a service account (api-keys:manage): sets revoked_at, so its key
    /// fails to resolve on the next request. Idempotent - an already-revoked
    /// account is a benign success. Unknown id is a NotFound
    /// (tenancy.service_account_not_found).
    /// </summary>
    Task<Result> RevokeServiceAccountAsync(
        Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken);

    // --- Enterprise SSO configuration (active tenant, request path under RLS) ---
    // A tenant configures its own OIDC IdP and claims its routing domains through
    // the tenant-admin API, gated by settings:manage (sso-and-scim.md section 3).
    // The OIDC sign-in flow itself lives in the Identity module and reads this
    // config through the ITenantSsoConfigReader platform port, never this facade.

    /// <summary>
    /// Sets (creates or replaces) the active tenant's enterprise-SSO configuration
    /// (settings:manage). The issuer MUST be an absolute https URL (a non-https
    /// issuer is refused, <c>tenancy.sso_issuer_insecure</c>, so the discovery/JWKS
    /// fetch cannot be tampered with); the client secret is write-only, stored only
    /// DataProtection-encrypted and never read back. Emits <c>tenancy.sso.configured</c>.
    /// </summary>
    Task<Result> SetSsoConfigAsync(
        Guid callerUserId,
        string issuer,
        string clientId,
        string clientSecret,
        bool enabled,
        CancellationToken cancellationToken);

    /// <summary>
    /// Claims an email domain for the active tenant's SSO routing (settings:manage).
    /// The claim is created UNVERIFIED and does not route until an operator approves
    /// it (DNS-TXT self-verification is a grow-into). A domain already claimed by ANY
    /// tenant is a Conflict (<c>tenancy.sso_domain_claimed</c>) on the global unique
    /// index - a domain is claimable by at most one tenant. Returns the new claim id.
    /// Emits <c>tenancy.sso.configured</c>.
    /// </summary>
    Task<Result<Guid>> ClaimSsoDomainAsync(
        Guid callerUserId, string domain, CancellationToken cancellationToken);

    // --- SCIM 2.0 Users provisioning (sso-and-scim.md section 5) ----------
    // A tenant mints a SCIM bearer through the tenant-admin API (settings:manage,
    // the same enterprise-integration admin surface as the SSO config). The bearer
    // then drives /scim/v2/Users under a DEDICATED auth scheme: it resolves
    // tenant-less to its tenant (the resolve below, on the bypass path), and every
    // Users operation runs RLS-scoped to THAT tenant on the request path.
    // Possession of the tid-scoped bearer IS the authority for the SCIM surface, so
    // the Users operations carry no permission gate; the token-management surface
    // does (settings:manage).

    /// <summary>
    /// Resolves a presented SCIM bearer by its SHA-256 hex hash to its tenant
    /// (sso-and-scim.md section 5): the tenant-less lookup on the bypass path,
    /// returning the tenant id for a LIVE token or null for every miss - unknown,
    /// revoked, or expired all collapse to null so a holder cannot probe which tokens
    /// exist. The Api-layer SCIM authentication handler calls this after hashing the
    /// raw token; the handler mints a tid-scoped, non-resolving principal on a hit and
    /// 401s on null.
    /// </summary>
    Task<Guid?> ResolveScimTokenAsync(string tokenHash, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a SCIM bearer (settings:manage) and returns the raw token ONCE (it is
    /// never retrievable again). An optional <paramref name="expiresAt"/> caps its
    /// life. Emits <c>tenancy.scim.token_rotated</c> (no secret on the payload).
    /// </summary>
    Task<Result<(Guid Id, string RawToken, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>>
        CreateScimTokenAsync(Guid callerUserId, DateTimeOffset? expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// Lists the active tenant's SCIM tokens (settings:manage): id, display prefix,
    /// and timestamps - NEVER the secret or the hash.
    /// </summary>
    Task<IReadOnlyList<(Guid Id, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt)>>
        ListScimTokensAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Rotates a SCIM token (settings:manage): mints a new secret on the same row and
    /// returns the new raw token ONCE. The old secret stops resolving immediately.
    /// Unknown id is a NotFound (<c>tenancy.scim_token_not_found</c>). Emits
    /// <c>tenancy.scim.token_rotated</c>.
    /// </summary>
    Task<Result<(string RawToken, string TokenPrefix)>>
        RotateScimTokenAsync(Guid callerUserId, Guid tokenId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes a SCIM token (settings:manage): sets revoked_at, so its secret fails to
    /// resolve on the next request. Idempotent - an already-revoked token is a benign
    /// success. Unknown id is a NotFound (<c>tenancy.scim_token_not_found</c>).
    /// </summary>
    Task<Result> RevokeScimTokenAsync(Guid callerUserId, Guid tokenId, CancellationToken cancellationToken);

    /// <summary>
    /// SCIM POST /Users: resolve-or-create the global user (born unverified,
    /// passwordless, so a later first SSO login claims the shell) and ensure a member
    /// of the token's tenant with the default member role. Idempotent on
    /// <paramref name="userName"/> (the email): a repeat provision returns the existing
    /// member with no duplicate. <paramref name="externalId"/> round-trips on a genuine
    /// create. <c>Created</c> is true only for a fresh membership. A blank / non-email
    /// userName is a Validation failure. Emits <c>tenancy.membership.created</c> only on
    /// a fresh membership.
    /// </summary>
    Task<Result<(Guid UserId, string Email, bool Active, string? ExternalId, bool Created)>>
        ProvisionScimUserAsync(string userName, string? externalId, CancellationToken cancellationToken);

    /// <summary>
    /// SCIM GET /Users/{id}: the member view for the token's tenant, or null when no
    /// such member exists here - including a user who is a member of ANOTHER tenant
    /// only (RLS makes their membership invisible, so it reads as 404, never a
    /// cross-tenant confirmation).
    /// </summary>
    Task<(Guid UserId, string Email, bool Active, string? ExternalId)?>
        GetScimUserAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// SCIM GET /Users?filter=userName eq "...": resolves the userName (email) to a
    /// member of the token's tenant, or null. This is the ONLY supported filter; any
    /// other filter yields an empty list at the endpoint.
    /// </summary>
    Task<(Guid UserId, string Email, bool Active, string? ExternalId)?>
        FindScimUserByUserNameAsync(string userName, CancellationToken cancellationToken);

    /// <summary>
    /// SCIM PUT active / DELETE: flips the member's status in place (Active &lt;-&gt;
    /// Suspended, a SOFT change preserving the row and grants). <c>active=false</c> and
    /// DELETE both suspend; <c>active=true</c> reactivates. Idempotent - a no-op when
    /// already in the target state. Suspending the tenant's last owner is refused
    /// (<c>tenancy.last_owner</c>). Unknown member is a NotFound. Emits
    /// <c>tenancy.member.suspended</c> / <c>tenancy.member.reactivated</c> on a genuine
    /// change.
    /// </summary>
    Task<Result<(Guid UserId, string Email, bool Active, string? ExternalId)>>
        SetScimUserActiveAsync(Guid userId, bool active, CancellationToken cancellationToken);
}
