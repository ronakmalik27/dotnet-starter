using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity;

/// <summary>
/// The only public surface of the Identity module (LLD section 1). Owns
/// accounts, tokens, sessions, consent, and profiles (F-01, F-02; HLD 3.1).
/// Starter.Api composes the HTTP endpoints over these commands (ADR-0011:
/// modules never self-host routes). Signatures use primitives and platform
/// contract types only: the module exports no other public type
/// (ModuleSurfaceTests). Reset and session management join with stories
/// #36-#40.
/// </summary>
public interface IIdentityApi
{
    /// <summary>
    /// FR-AUTH-01 registration. Success is deliberately empty and
    /// identical whether the email was fresh or already registered
    /// (SRS 5.3 no-enumeration); an existing owner gets a "was this you?"
    /// notice out of band. Failures are Validation only (email shape,
    /// password policy, breached password).
    /// </summary>
    Task<Result> RegisterAsync(string email, string password, CancellationToken cancellationToken);

    /// <summary>
    /// FR-AUTH-04 login: verifies the password credential and issues an
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
    /// FR-AUTH-04 rotation: retires the presented refresh token and issues
    /// a new pair in the same family. Reuse of a retired token revokes the
    /// whole family and notifies the user; a bumped token version rejects
    /// here immediately (doc 10 4.2). Every failure is the same
    /// Unauthorized error.
    /// </summary>
    Task<Result<IssuedTokens>> RefreshAsync(
        string refreshToken,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// FR-AUTH-03 Google sign-in (doc 10 4.5: code flow + PKCE + nonce).
    /// The client hands over its authorization code, PKCE verifier,
    /// redirect URI, and the nonce it bound into the authorization
    /// request; the server redeems and validates them, applies the SRS
    /// 5.3 linking rules, and issues the same method-agnostic session a
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
    /// FR-AUTH-03 dual-method: the authenticated, currently passwordless
    /// account sets its first password (a second auth_methods row).
    /// Accounts that already hold a password method fail Conflict
    /// (auth.password_change_not_implemented) until FR-AUTH-10
    /// change-password lands; the endpoint answers 501 for that code.
    /// </summary>
    Task<Result> SetPasswordAsync(Guid userId, string newPassword, CancellationToken cancellationToken);

    /// <summary>
    /// FR-AUTH-02 consumption: marks the verify_email token used (single
    /// use, atomic) and the account verified. Unknown, used, and expired
    /// tokens fail with one generic Validation error.
    /// </summary>
    Task<Result> VerifyEmailAsync(string token, CancellationToken cancellationToken);

    /// <summary>
    /// The render-only half of the doc 10 4.7 split: reports the token's
    /// state without consuming or invalidating anything. Unknown tokens
    /// are a NotFound failure.
    /// </summary>
    Task<Result<VerificationTokenStatus>> GetVerificationTokenStatusAsync(
        string token,
        CancellationToken cancellationToken);

    /// <summary>
    /// FR-AUTH-02 resend, rate-limited 3/h per account against the
    /// issuance history (doc 10 4.6). Success for an already-verified
    /// account is a no-op.
    /// </summary>
    Task<Result> ResendVerificationEmailAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// The `vrf` capability gate's read (doc 10 section 5): true only for
    /// an existing account with a verified email. Fails closed - a missing
    /// row is false.
    /// </summary>
    Task<bool> IsEmailVerifiedAsync(Guid userId, CancellationToken cancellationToken);
}
