using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Starter.Platform.Auth;

namespace Starter.Identity.Tokens;

/// <summary>
/// Issues the access JWT: ES256, 15-minute expiry, exactly the
/// sub / sid / ver claims - no roles (roles are scoped per-entity, resolved
/// per-request) - plus the optional tid claim naming the active tenant. The
/// verifying half is the platform's StarterJwtAuthentication; both sides share
/// the StarterAuth constants.
/// </summary>
internal sealed class AccessTokenIssuer(ECDsaSecurityKey signingKey)
{
    private static readonly JsonWebTokenHandler Handler = new();

    private readonly SigningCredentials _credentials =
        new(signingKey, SecurityAlgorithms.EcdsaSha256);

    /// <summary>
    /// Mints the access token. <paramref name="tenantId"/> adds the tid claim
    /// when non-null (a tenant-bound session); a tenant-less session (login)
    /// leaves it out, so tenant resolution falls back to another source.
    /// </summary>
    public string Issue(Guid userId, Guid sessionId, int tokenVersion, DateTimeOffset now, Guid? tenantId = null)
    {
        var claims = new Dictionary<string, object>
        {
            [StarterClaims.Sub] = userId.ToString(),
            [StarterClaims.Sid] = sessionId.ToString(),
            [StarterClaims.Ver] = tokenVersion,
        };
        if (tenantId is Guid tenant)
        {
            claims[StarterClaims.Tid] = tenant.ToString();
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = StarterAuth.Issuer,
            Audience = StarterAuth.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.UtcDateTime.Add(StarterAuth.AccessTokenLifetime),
            SigningCredentials = _credentials,
            Claims = claims,
        };

        return Handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Mints the SHORT impersonation access token (multi-tenancy.md section 7):
    /// sub is the subject being acted as (the target user, or the acting admin
    /// when no target user was named), tid is the target tenant so RLS scopes
    /// the session, and the imp / impgrant claims name the acting admin and the
    /// backing grant so every request is attributable and the per-request guard
    /// can re-check the exact grant. There is NO sid claim (the token is not
    /// backed by a refresh session and is never refreshable). exp is the grant's
    /// absolute expiry, so the token and its grant die together (never later
    /// than the 15-minute access cap, enforced by the caller when it computes
    /// the grant window). ver is the subject's current token version, so the
    /// token validates exactly like a normal one.
    /// </summary>
    public string IssueImpersonation(
        Guid subjectUserId,
        Guid tenantId,
        int subjectTokenVersion,
        Guid actingAdminUserId,
        Guid grantId,
        DateTimeOffset now,
        DateTimeOffset expiresAt)
    {
        var claims = new Dictionary<string, object>
        {
            [StarterClaims.Sub] = subjectUserId.ToString(),
            [StarterClaims.Tid] = tenantId.ToString(),
            [StarterClaims.Ver] = subjectTokenVersion,
            [StarterClaims.Imp] = actingAdminUserId.ToString(),
            [StarterClaims.ImpGrant] = grantId.ToString(),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = StarterAuth.Issuer,
            Audience = StarterAuth.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = _credentials,
            Claims = claims,
        };

        return Handler.CreateToken(descriptor);
    }
}
