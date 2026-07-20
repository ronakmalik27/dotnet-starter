using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Starter.Platform.Auth;

namespace Starter.Identity.Tokens;

/// <summary>
/// Issues the doc 10 4.2 access JWT: ES256, 15-minute expiry, exactly the
/// sub / sid / ver claims - no roles (INV-5: roles are per-trip, resolved
/// per-request). The verifying half is the platform's
/// StarterJwtAuthentication; both sides share the StarterAuth constants.
/// </summary>
internal sealed class AccessTokenIssuer(ECDsaSecurityKey signingKey)
{
    private static readonly JsonWebTokenHandler Handler = new();

    private readonly SigningCredentials _credentials =
        new(signingKey, SecurityAlgorithms.EcdsaSha256);

    public string Issue(Guid userId, Guid sessionId, int tokenVersion, DateTimeOffset now)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = StarterAuth.Issuer,
            Audience = StarterAuth.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.UtcDateTime.Add(StarterAuth.AccessTokenLifetime),
            SigningCredentials = _credentials,
            Claims = new Dictionary<string, object>
            {
                [StarterClaims.Sub] = userId.ToString(),
                [StarterClaims.Sid] = sessionId.ToString(),
                [StarterClaims.Ver] = tokenVersion,
            },
        };

        return Handler.CreateToken(descriptor);
    }
}
