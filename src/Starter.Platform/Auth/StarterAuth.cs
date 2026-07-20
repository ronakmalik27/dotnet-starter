namespace Starter.Platform.Auth;

/// <summary>
/// The doc 10 section 4.2 token contract constants, shared by the issuer
/// (Starter.Identity) and the verifier (the host's JWT bearer middleware) so
/// the two can never drift apart. Values are fixed by the security design,
/// not configuration: only the signing key varies per environment.
/// </summary>
public static class StarterAuth
{
    /// <summary>Issuer and audience of every Starter access token.</summary>
    public const string Issuer = "starter";

    /// <summary>Single audience for the monolith (HLD 3.1).</summary>
    public const string Audience = "starter";

    /// <summary>Access token lifetime: exp &lt;= 15 min (FR-AUTH-04).</summary>
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Refresh-token family lifetime: 30 days, absolute from login
    /// (doc 10 4.2). Rotation never extends it: a rotated session row
    /// inherits the family deadline.
    /// </summary>
    public static readonly TimeSpan RefreshFamilyLifetime = TimeSpan.FromDays(30);

    /// <summary>
    /// Verification clock-skew allowance. Deliberately below the 5-minute
    /// framework default: tokens live 15 minutes, and the SRS 5.3
    /// clock-skew edge is handled by serving the server time in every 401
    /// body so clients compensate rather than the server being lenient.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);
}

/// <summary>
/// Claim names of the access JWT (doc 10 4.2): subject, session, and the
/// user's global token version. No role claims by design - roles are
/// per-trip and resolved per-request (INV-5).
/// </summary>
public static class StarterClaims
{
    /// <summary>The user id (JWT registered claim).</summary>
    public const string Sub = "sub";

    /// <summary>The session id backing this token.</summary>
    public const string Sid = "sid";

    /// <summary>
    /// The user's global token version, bumped for cheap mass revocation
    /// and enforced at refresh only (doc 10 4.2).
    /// </summary>
    public const string Ver = "ver";
}
