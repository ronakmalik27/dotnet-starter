namespace Starter.Platform.Http;

/// <summary>
/// The stable problem type slugs. Slugs never change
/// meaning; new error conditions get new slugs in the
/// same change as the endpoint that produces them. A slug is a valid RFC 9457
/// type URI (scheme "starter").
/// </summary>
public static class ProblemTypes
{
    /// <summary>422: request shape or field values are wrong.</summary>
    public const string Validation = "starter:validation";

    /// <summary>404: resource absent, including non-membership - never 403.</summary>
    public const string NotFound = "starter:not-found";

    /// <summary>409: optimistic-concurrency version mismatch.</summary>
    public const string VersionConflict = "starter:version-conflict";

    /// <summary>409: same idempotency key, first request still executing.</summary>
    public const string IdempotencyInFlight = "starter:idempotency-in-flight";

    /// <summary>401: missing or invalid authentication.</summary>
    public const string Unauthorized = "starter:unauthorized";

    /// <summary>
    /// 403: the caller is authenticated but not permitted to act on this
    /// resource - the resource-based owner check (ResourceOperations against
    /// an IOwnedResource) did not grant access. Distinct from the 404-for-
    /// non-membership rule: an existence-sensitive resource returns 404 to
    /// avoid confirming it exists, whereas a non-sensitive owned resource
    /// answers 403 honestly.
    /// </summary>
    public const string Forbidden = "starter:forbidden";

    /// <summary>429: rate limit exceeded.</summary>
    public const string RateLimited = "starter:rate-limited";

    /// <summary>
    /// 403: the caller is authenticated but the account's email is not
    /// verified, and this endpoint carries the `vrf` capability. Deliberately
    /// not 404: the 404-for-non-membership rule hides restricted resources,
    /// whereas verification is the caller's own account state and the
    /// UX needs the reason to render inline.
    /// </summary>
    public const string VerificationRequired = "starter:verification-required";

    /// <summary>400 family (400/413/431/..): the request could not be read - malformed body, oversized payload.</summary>
    public const string BadRequest = "starter:bad-request";

    /// <summary>
    /// 400: the endpoint is tenant-scoped but no active tenant could be
    /// resolved from the request (no tid claim, subdomain, path prefix, or
    /// X-Tenant header). The caller must address the request to a tenant.
    /// </summary>
    public const string TenantRequired = "starter:tenant-required";

    /// <summary>
    /// 409: self-serve signup asked for a tenant slug that is already taken. A
    /// slug is caller-supplied and not a secret, so confirming it is taken is
    /// fine (unlike the enumeration-safe email path).
    /// </summary>
    public const string TenantSlugTaken = "starter:tenant-slug-taken";

    /// <summary>
    /// 404: the caller is not an active member of the named tenant (or the
    /// tenant does not exist - the two collapse to one answer). Deliberately 404
    /// not 403, so a non-member cannot confirm the tenant exists (the same
    /// cross-tenant 404 posture the isolation boundary takes).
    /// </summary>
    public const string TenantMembershipNotFound = "starter:tenant-membership-not-found";

    /// <summary>
    /// 403: the caller is an authenticated member of the active tenant but their
    /// role is below the minimum the endpoint requires (RBAC layer 2 -
    /// owner &gt; admin &gt; member). Not 404: this is the caller's own tenant, so
    /// the honest answer is "you lack the role", not "no such thing".
    /// </summary>
    public const string TenantRoleRequired = "starter:tenant-role-required";

    /// <summary>
    /// 403: the caller is an authenticated member of the active tenant but their
    /// effective permission set (system-role permissions plus tenant-scope
    /// custom-role grants) does not include the permission the endpoint requires
    /// (RBAC section 13, the RequirePermission gate). Not 404: this is the
    /// caller's own tenant, so the honest answer is "you lack the permission".
    /// </summary>
    public const string PermissionRequired = "starter:permission-required";

    /// <summary>
    /// 409: a custom role with that key already exists in the owning scope (the
    /// tenant for a tenant-owned role). A role key is caller-supplied and not a
    /// secret, so a definite answer is fine.
    /// </summary>
    public const string TenantRoleKeyTaken = "starter:tenant-role-key-taken";

    /// <summary>
    /// 404: the request named a workspace that does not exist under the active
    /// tenant (multi-tenancy.md section 12). Because a workspace row is
    /// tenant-owned under RLS, a workspaceId from another tenant is invisible and
    /// collapses to this same answer, so the workspace-scoped surface never
    /// confirms a workspace exists in a tenant the caller cannot see. Deliberately
    /// 404, not 403: 403 (permission-required) is for a workspace that DOES exist
    /// but where the caller lacks the permission.
    /// </summary>
    public const string WorkspaceNotFound = "starter:workspace-not-found";

    /// <summary>
    /// 409: self-serve or admin workspace creation asked for a slug already taken
    /// within the tenant. A slug is caller-supplied and not a secret, so a
    /// definite answer is fine (the citext unique index on (tenant_id, slug) is
    /// the backstop).
    /// </summary>
    public const string WorkspaceSlugTaken = "starter:workspace-slug-taken";

    /// <summary>
    /// 409: the workspace is archived, so a write to a resource inside it is
    /// refused (multi-tenancy.md section 20 - an archived workspace is read-only).
    /// Reads stay served; only mutating workspace-scoped routes carry the gate.
    /// Unarchiving the workspace (a tenant-scope management op) lifts it.
    /// </summary>
    public const string WorkspaceArchived = "starter:workspace-archived";

    /// <summary>
    /// 409: the custom role has assignments, so it cannot be deleted; its grants
    /// must be revoked or reassigned first, so access never silently vanishes or
    /// dangles.
    /// </summary>
    public const string TenantRoleInUse = "starter:tenant-role-in-use";

    /// <summary>
    /// 409: the tenant is at its seat limit, so an invitation cannot be accepted
    /// into it. A seat is a countable, non-secret resource, so a definite answer
    /// is fine. Concurrent accepts serialize on a tenant row lock, so the count
    /// can never overrun the limit.
    /// </summary>
    public const string TenantSeatLimitReached = "starter:tenant-seat-limit-reached";

    /// <summary>
    /// 404: the presented invitation token is unknown, already accepted, expired,
    /// or does not match the authenticated caller's email. Every miss collapses
    /// to this one answer so a holder cannot probe which invitations exist.
    /// </summary>
    public const string TenantInvitationInvalid = "starter:tenant-invitation-invalid";

    /// <summary>
    /// 409: the operation would leave the tenant with no owner (demoting or
    /// removing the last owner). Ownership moves through transfer-ownership, never
    /// by dropping the only owner.
    /// </summary>
    public const string TenantLastOwner = "starter:tenant-last-owner";

    /// <summary>
    /// 409: the target account is already an active member of the tenant (or a
    /// pending invitation already covers it), so the membership cannot be created
    /// again. The unique (tenant_id, user_id) index is the backstop.
    /// </summary>
    public const string TenantMembershipConflict = "starter:tenant-membership-conflict";

    /// <summary>
    /// 403: the caller is authenticated but is not a platform super-admin, and
    /// this endpoint is on the platform control plane (multi-tenancy.md section
    /// 7). Platform power is separate from any tenant role - it is membership of
    /// platform.platform_admins, never a tenant membership. Not 404: the
    /// platform surface is a known, documented plane, so the honest answer is
    /// "you are not a platform admin".
    /// </summary>
    public const string PlatformAdminRequired = "starter:platform-admin-required";

    /// <summary>
    /// 409: revoking this platform admin would leave the platform with none, so
    /// the operation is refused (the lockout guard). A platform must always have
    /// at least one super-admin; the first is seeded out of band and this rule
    /// keeps the last one from being removed through the API.
    /// </summary>
    public const string PlatformLastAdmin = "starter:platform-last-admin";

    /// <summary>
    /// 403: the request is acting under an impersonation token (it carries the
    /// imp claim) and this endpoint is destructive or irreversible, so it is
    /// refused (multi-tenancy.md section 7, the conservative default a real app
    /// tightens per endpoint). Not 404: the resource may well exist; the honest
    /// answer is "not while impersonating".
    /// </summary>
    public const string ImpersonationForbidden = "starter:impersonation-forbidden";

    /// <summary>
    /// 401: the impersonation session backing this token is over - the grant was
    /// ended early or has passed its expiry - so the per-request guard rejects
    /// it immediately, not only when the token itself expires (multi-tenancy.md
    /// section 7). The caller is no longer authenticated for this session.
    /// </summary>
    public const string ImpersonationEnded = "starter:impersonation-ended";

    /// <summary>
    /// 403: the caller is an active member but the target tenant is suspended or
    /// deleted, so a NEW tid token cannot be minted for it (multi-tenancy.md
    /// section 6 lifecycle). Existing tid tokens age out within the 15-minute
    /// access window; this only blocks fresh re-entry. Impersonation deliberately
    /// does not use this path (a support admin may enter a suspended tenant).
    /// </summary>
    public const string TenantInactive = "starter:tenant-inactive";

    /// <summary>
    /// 409: a tenant-lifecycle transition was requested from a state that does
    /// not allow it (suspending a non-active tenant, reactivating a non-suspended
    /// one, or deleting an already-deleted one). A tenant's status is a definite,
    /// non-secret fact to a platform admin, so a definite answer is fine.
    /// </summary>
    public const string TenantStateConflict = "starter:tenant-state-conflict";

    /// <summary>405: the HTTP method is not supported on this route.</summary>
    public const string MethodNotAllowed = "starter:method-not-allowed";

    /// <summary>415: the request content type is not accepted by this endpoint.</summary>
    public const string UnsupportedMediaType = "starter:unsupported-media-type";

    /// <summary>
    /// 409: the Google-verified email already belongs to a VERIFIED
    /// account and the request carried no live session for it (linking
    /// into a verified account requires a signed-in
    /// confirmation; silent merge never happens). The client signs the
    /// user in to the existing account and retries the Google exchange
    /// with that access token attached.
    /// </summary>
    public const string LinkConfirmationRequired = "starter:link-confirmation-required";

    /// <summary>500: an unexpected server fault; details stay in the logs.</summary>
    public const string Internal = "starter:internal";

    /// <summary>
    /// 501: the request names a documented capability whose implementation
    /// has not landed yet (e.g. an optional field accepted before its
    /// feature ships). Failing loudly
    /// beats silently ignoring the field.
    /// </summary>
    public const string NotImplemented = "starter:not-implemented";
}
