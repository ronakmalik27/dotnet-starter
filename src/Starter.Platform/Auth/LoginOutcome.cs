namespace Starter.Platform.Auth;

/// <summary>
/// The two shapes a successful password login can take. A plain account gets
/// its session immediately (<see cref="Tokens"/>); an MFA-enabled account
/// (multi-factor-auth, mfa-totp.md section 5) gets an
/// <see cref="MfaChallenge"/> instead - the password proved the first factor,
/// and a second endpoint exchanges the challenge plus a TOTP or recovery code
/// for the real session. A closed hierarchy (private base constructor) so the
/// endpoint maps exactly the two cases; <c>Result&lt;IssuedTokens&gt;</c> could
/// not carry the third outcome without a dual-nullable hack. Lives in the
/// platform beside <see cref="IssuedTokens"/>, the token contract the transport
/// layers share (the Identity module exports no type beyond its Api interface).
/// </summary>
public abstract record LoginOutcome
{
    private LoginOutcome()
    {
    }

    /// <summary>The account has no confirmed MFA: the login issued a session outright.</summary>
    public sealed record Tokens(IssuedTokens Issued) : LoginOutcome;

    /// <summary>
    /// The account has confirmed MFA: the password verified, but no session is
    /// issued. <paramref name="Token"/> is a short-lived, distinct-audience
    /// challenge JWT the mfa-verify endpoint exchanges (with a valid code) for
    /// the session. <paramref name="ExpiresInSeconds"/> is the challenge's
    /// lifetime.
    /// </summary>
    public sealed record MfaChallenge(string Token, int ExpiresInSeconds) : LoginOutcome;
}
