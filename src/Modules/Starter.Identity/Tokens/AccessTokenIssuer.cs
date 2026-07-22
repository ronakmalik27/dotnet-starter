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
}
