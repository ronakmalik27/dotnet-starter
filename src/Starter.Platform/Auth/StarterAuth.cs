namespace Starter.Platform.Auth;

/// <summary>
/// The token contract constants, shared by the issuer
/// (Starter.Identity) and the verifier (the host's JWT bearer middleware) so
/// the two can never drift apart. Values are fixed by the security design,
/// not configuration: only the signing key varies per environment.
/// </summary>
public static class StarterAuth
{
    /// <summary>Issuer and audience of every Starter access token.</summary>
    public const string Issuer = "starter";

    /// <summary>Single audience for the monolith.</summary>
    public const string Audience = "starter";

    /// <summary>Access token lifetime: exp &lt;= 15 min.</summary>
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Refresh-token family lifetime: 30 days, absolute from login.
    /// Rotation never extends it: a rotated session row
    /// inherits the family deadline.
    /// </summary>
    public static readonly TimeSpan RefreshFamilyLifetime = TimeSpan.FromDays(30);

    /// <summary>
    /// Verification clock-skew allowance. Deliberately below the 5-minute
    /// framework default: tokens live 15 minutes, and the
    /// clock-skew edge case is handled by serving the server time in every 401
    /// body so clients compensate rather than the server being lenient.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);
}

/// <summary>
/// Claim names of the access JWT: subject, session, and the
/// user's global token version. No role claims by design - roles are
/// per-entity and resolved per-request.
/// </summary>
public static class StarterClaims
{
    /// <summary>The user id (JWT registered claim).</summary>
    public const string Sub = "sub";

    /// <summary>The session id backing this token.</summary>
    public const string Sid = "sid";

    /// <summary>
    /// The active tenant id for a tenant-scoped access token. Read by tenant
    /// resolution as the authoritative source once a caller has signed in for
    /// a tenant. Absent until the Tenancy module mints it; a token without it
    /// simply resolves the tenant from another source (header, path, subdomain).
    /// </summary>
    public const string Tid = "tid";

    /// <summary>
    /// The user's global token version, bumped for cheap mass revocation
    /// and enforced at refresh only.
    /// </summary>
    public const string Ver = "ver";

    /// <summary>
    /// The caller's principal type (service-accounts.md section 3): present on an
    /// API-key principal minted by the ApiKey authentication scheme, carrying
    /// <see cref="PrincipalTypes.ServiceAccount"/>. A JWT access token never
    /// carries it, so the permission gate defaults an absent claim to
    /// <see cref="PrincipalTypes.User"/> - a human caller. The value is one of the
    /// <see cref="PrincipalTypes"/> literals.
    /// </summary>
    public const string Pt = "pt";

    /// <summary>
    /// Present only on an impersonation access token: the acting platform
    /// admin's user id. It is a signed claim, so it is unforgeable and every
    /// impersonated request is attributable to the human behind it (multi-
    /// tenancy.md section 7). Its presence is also the marker the per-request
    /// impersonation guard and the destructive-op filter key on: a normal token
    /// never carries it.
    /// </summary>
    public const string Imp = "imp";

    /// <summary>
    /// Present only on an impersonation access token: the
    /// platform.impersonation_grants row id backing the session. The per-request
    /// guard reads it to re-check the exact grant (ended_at, expires_at) so
    /// ending a session takes effect on the very next request, not at token
    /// expiry.
    /// </summary>
    public const string ImpGrant = "impgrant";
}
