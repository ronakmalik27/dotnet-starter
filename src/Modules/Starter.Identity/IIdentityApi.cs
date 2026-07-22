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
/// staging / verification-email / session-issue seam), so the tenancy
/// provisioner can depend on that port without the Tenancy module referencing
/// this one. The composition root registers the same instance for both.
/// </para>
/// </summary>
public interface IIdentityApi : ITenantProvisioningIdentity
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
    /// Login: verifies the password credential and issues an
    /// ES256 access JWT plus a fresh refresh-token family. Every failure
    /// is the same Unauthorized error.
    /// </summary>
    Task<Result<IssuedTokens>> LoginAsync(
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
    /// </summary>
    Task<Result<TenantAccessToken>> SelectTenantAsync(
        Guid userId,
        Guid sessionId,
        Guid tenantId,
        CancellationToken cancellationToken);
}
