using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity;

/// <summary>
/// The only public surface of the Identity module. Owns accounts,
/// credentials, tokens, sessions, and email verification. Starter.Api
/// composes the HTTP endpoints over these commands (modules never
/// self-host routes). Signatures use primitives and platform contract
/// types only: the module exports no other public type (ModuleSurfaceTests).
/// <para>
/// It inherits <see cref="ITenantProvisioningIdentity"/> (the platform-declared
/// staging / verification-email / session-issue seam) and
/// <see cref="IUserDirectory"/> (the minimal user-lookup seam the tenancy invite
/// and accept flows read), so those modules depend on the platform ports without
/// referencing this one. The composition root registers the same instance for all.
/// </para>
/// </summary>
public interface IIdentityApi : ITenantProvisioningIdentity, IUserDirectory
{
    /// <summary>
    /// Registration. Success is deliberately empty and
    /// identical whether the email was fresh or already registered
    /// (no-account-enumeration); an existing owner gets a "was this you?"
    /// notice out of band. Failures are Validation only (email shape,
    /// password policy, breached password).
    /// </summary>
    Task<Result> RegisterAsync(string email, string password, CancellationToken cancellationToken);

    /// <summary>
    /// Login: verifies the password credential and returns a
    /// <see cref="LoginOutcome"/>. A plain account gets
    /// <see cref="LoginOutcome.Tokens"/> (an ES256 access JWT plus a fresh
    /// refresh-token family), exactly as before. An account with confirmed MFA
    /// gets <see cref="LoginOutcome.MfaChallenge"/> instead: the password
    /// proved the first factor, but no session issues until
    /// <see cref="VerifyMfaAsync"/> exchanges the challenge plus a code
    /// (mfa-totp.md section 5). Every credential failure is the same
    /// Unauthorized error.
    /// </summary>
    Task<Result<LoginOutcome>> LoginAsync(
        string email,
        string password,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// Rotation: retires the presented refresh token and issues
    /// a new pair in the same family. Reuse of a retired token revokes the
    /// whole family and notifies the user; a bumped token version rejects
    /// here immediately. Every failure is the same
    /// Unauthorized error.
    /// </summary>
    Task<Result<IssuedTokens>> RefreshAsync(
        string refreshToken,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// Google sign-in (code flow + PKCE + nonce).
    /// The client hands over its authorization code, PKCE verifier,
    /// redirect URI, and the nonce it bound into the authorization
    /// request; the server redeems and validates them, applies the
    /// account-linking rules, and issues the same method-agnostic session a
    /// password login gets. <paramref name="confirmedUserId"/> is the
    /// authenticated caller when the request carried a valid access token
    /// - the signed-in confirmation that permits linking into a VERIFIED
    /// existing account; without it that case fails Conflict
    /// (auth.google_link_confirmation_required) instead of silently
    /// merging. Exchange or validation failures are one generic
    /// Unauthorized; auth.google_not_configured flags a host without
    /// Google wiring (the endpoint answers 501).
    /// </summary>
    Task<Result<IssuedTokens>> SignInWithGoogleAsync(
        string code,
        string codeVerifier,
        string redirectUri,
        string nonce,
        Guid? confirmedUserId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// Dual-method: the authenticated, currently passwordless
    /// account sets its first password (a second auth_methods row).
    /// Accounts that already hold a password method fail Conflict
    /// (auth.password_change_not_implemented); the endpoint routes a request
    /// carrying a current password to <see cref="ChangePasswordAsync"/>
    /// instead, so a caller never reaches this conflict on the happy path.
    /// </summary>
    Task<Result> SetPasswordAsync(Guid userId, string newPassword, CancellationToken cancellationToken);

    /// <summary>
    /// Change password: the authenticated account replaces its existing
    /// password. The current password is verified against the stored hash;
    /// any mismatch (wrong password, no password method, or a disabled one)
    /// is the same generic Validation failure
    /// (auth.current_password_incorrect) on the current-password field. On
    /// success the hash is rotated and the token version is bumped, so every
    /// other session is soft-revoked at its next refresh.
    /// </summary>
    Task<Result> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken);

    /// <summary>
    /// Forgot password: mints a single-use reset token for an active account
    /// and emails the reset link. Success is deliberately empty and
    /// identical whether or not the account exists (no-account-enumeration,
    /// exactly like <see cref="RegisterAsync"/>); issuance is rate-limited
    /// per account. The raw token reaches the owner only through the emailed
    /// link, never on the event spine.
    /// </summary>
    Task<Result> RequestPasswordResetAsync(string email, CancellationToken cancellationToken);

    /// <summary>
    /// Reset password: consumes a single-use reset token (atomic) and sets
    /// or replaces the account's password, creating the password method for
    /// a previously password-less account. Bumps the token version, so every
    /// session is soft-revoked at its next refresh. Unknown, used, and
    /// expired tokens fail with one generic Validation error; a weak new
    /// password fails the password policy without consuming the token.
    /// </summary>
    Task<Result> ResetPasswordAsync(string token, string newPassword, CancellationToken cancellationToken);

    /// <summary>
    /// Consumption: marks the verify_email token used (single
    /// use, atomic) and the account verified. Unknown, used, and expired
    /// tokens fail with one generic Validation error.
    /// </summary>
    Task<Result> VerifyEmailAsync(string token, CancellationToken cancellationToken);

    /// <summary>
    /// The render-only half of the verification-status split: reports the token's
    /// state without consuming or invalidating anything. Unknown tokens
    /// are a NotFound failure.
    /// </summary>
    Task<Result<VerificationTokenStatus>> GetVerificationTokenStatusAsync(
        string token,
        CancellationToken cancellationToken);

    /// <summary>
    /// Resend, rate-limited 3/h per account against the
    /// issuance history. Success for an already-verified
    /// account is a no-op.
    /// </summary>
    Task<Result> ResendVerificationEmailAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// The `vrf` capability gate's read: true only for
    /// an existing account with a verified email. Fails closed - a missing
    /// row is false.
    /// </summary>
    Task<bool> IsEmailVerifiedAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// MFA enrollment (mfa-totp.md section 4). Authenticated + a fresh current
    /// password (step-up, security-equivalent to changing a password): mints a
    /// 20-byte secret, stores it encrypted and UNCONFIRMED, and returns the
    /// otpauth URI + base32 secret (shown once). Does NOT yet enable MFA. A
    /// wrong current password is the generic auth.current_password_incorrect
    /// Validation failure; a re-enroll leaves an already-active secret intact.
    /// </summary>
    Task<Result<MfaEnrollment>> EnrollMfaAsync(
        Guid userId,
        string currentPassword,
        CancellationToken cancellationToken);

    /// <summary>
    /// MFA confirmation (mfa-totp.md section 4). Authenticated + a fresh
    /// current password + a code from the authenticator: verifies the code
    /// against the pending secret, enables MFA, and returns 10 recovery codes
    /// (shown once, stored hashed). A wrong current password fails
    /// auth.current_password_incorrect; a wrong code fails auth.mfa_code_invalid
    /// and does not confirm.
    /// </summary>
    Task<Result<MfaRecoveryCodes>> ConfirmMfaAsync(
        Guid userId,
        string currentPassword,
        string code,
        CancellationToken cancellationToken);

    /// <summary>
    /// The second step of an MFA login (mfa-totp.md section 5): exchanges a
    /// valid challenge token plus a TOTP or recovery code for the real session
    /// (tenant-less, like a normal login). Verifies are brute-force throttled
    /// per user; a burned recovery code never works again. Every failure is
    /// the same Unauthorized error.
    /// </summary>
    Task<Result<IssuedTokens>> VerifyMfaAsync(
        string challengeToken,
        string code,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// Disable MFA (mfa-totp.md section 7). Authenticated + a fresh TOTP or
    /// recovery code: re-proving the second factor deletes the credential and
    /// all recovery codes, and login reverts to one step. A wrong code fails
    /// auth.mfa_code_invalid.
    /// </summary>
    Task<Result> DisableMfaAsync(Guid userId, string code, CancellationToken cancellationToken);

    /// <summary>
    /// Regenerate recovery codes (mfa-totp.md section 6). Authenticated + a
    /// fresh TOTP code: replaces all prior codes with a new set of 10 (shown
    /// once, stored hashed). A wrong code fails auth.mfa_code_invalid.
    /// </summary>
    Task<Result<MfaRecoveryCodes>> RegenerateRecoveryCodesAsync(
        Guid userId,
        string code,
        CancellationToken cancellationToken);

    // StageRegistrationAsync, SendVerificationEmailAsync, and IssueSessionForAsync
    // are inherited from ITenantProvisioningIdentity (the platform-declared
    // provisioning seam), so the tenancy module can depend on that port without
    // referencing this module. SelectTenantAsync stays here: only the endpoint
    // layer calls it, through IIdentityApi.

    /// <summary>
    /// The tenant-switch mint: reissues the access token for an existing live
    /// session (proved to belong to <paramref name="userId"/>), now bound to
    /// <paramref name="tenantId"/> and carrying its tid. Same session and
    /// refresh family, no new refresh token; the tenant is stamped on the
    /// session row so a later refresh preserves it. A revoked, expired, or
    /// version-stale session is a generic Unauthorized.
    /// <para>
    /// <paramref name="sessionMaxSeconds"/> is the tenant's session-lifetime
    /// override (role-templates-and-policy-defaults.md section 5), resolved by the
    /// endpoint through <see cref="Starter.Platform.Auth.ITenantSessionPolicyReader"/>
    /// and passed in (this mint is endpoint-mediated). The issued token's lifetime is
    /// <c>min(platform default, override)</c>; null inherits the platform default.
    /// </para>
    /// </summary>
    Task<Result<TenantAccessToken>> SelectTenantAsync(
        Guid userId,
        Guid sessionId,
        Guid tenantId,
        int? sessionMaxSeconds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Mints the SHORT impersonation access token for a platform-admin session
    /// (multi-tenancy.md section 7). Called only after the Tenancy control plane
    /// has committed the grant row and its ImpersonationStarted event, so a token
    /// never exists without its audit record. The token's sub is
    /// <paramref name="subjectUserId"/> (the target user, or the acting admin
    /// when no target user was named), tid is <paramref name="tenantId"/>, imp /
    /// impgrant name <paramref name="actingAdminUserId"/> and
    /// <paramref name="grantId"/>, and exp is <paramref name="expiresAt"/> (the
    /// grant's absolute expiry - the token and the grant die together). No
    /// refresh token; impersonation is not refreshable. An absent or inactive
    /// subject is a generic Unauthorized.
    /// </summary>
    Task<Result<TenantAccessToken>> IssueImpersonationTokenAsync(
        Guid subjectUserId,
        Guid tenantId,
        Guid actingAdminUserId,
        Guid grantId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);
}
