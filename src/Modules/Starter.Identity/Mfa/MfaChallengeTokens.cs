using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Starter.Platform.Auth;

namespace Starter.Identity.Mfa;

/// <summary>A minted MFA challenge token and the lifetime (seconds) it carries.</summary>
internal readonly record struct MintedChallenge(string Token, int ExpiresInSeconds);

/// <summary>
/// Mints and validates the MFA challenge token (mfa-totp.md section 5): a
/// signed ES256 JWT with a DISTINCT audience (<see cref="ChallengeAudience"/>,
/// NOT <see cref="StarterAuth.Audience"/>), <c>sub = userId</c>, a ~5-minute
/// expiry, and no <c>sid</c>. Because the app's only registered JWT bearer
/// scheme validates <see cref="StarterAuth.Audience"/>, a challenge token is
/// rejected outright by normal access-token authentication - it proves only
/// "first factor passed" and can never act as an access token. The mint and
/// validate are explicit paths because <c>AccessTokenIssuer</c> hardcodes the
/// access audience; the mfa-verify handler validates by calling
/// <see cref="JsonWebTokenHandler.ValidateTokenAsync"/> with these dedicated
/// parameters INSIDE the handler, never through the [Authorize] pipeline
/// (which would 401 on the audience before the handler runs).
/// </summary>
internal sealed class MfaChallengeTokens
{
    /// <summary>The distinct challenge-token audience, never the access-token audience.</summary>
    public const string ChallengeAudience = "mfa-challenge";

    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private static readonly JsonWebTokenHandler Handler = new();

    private readonly SigningCredentials _credentials;
    private readonly TokenValidationParameters _validation;

    public MfaChallengeTokens(ECDsaSecurityKey signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        _credentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256);
        _validation = new TokenValidationParameters
        {
            ValidIssuer = StarterAuth.Issuer,
            ValidAudience = ChallengeAudience,
            IssuerSigningKey = signingKey,
            // ES256 only, like the access-token verifier: alg=none and every
            // other algorithm fails before signature checking.
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = StarterAuth.ClockSkew,
        };
    }

    /// <summary>Mints a challenge token for a user whose first factor just passed.</summary>
    public MintedChallenge Mint(Guid userId, DateTimeOffset now)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = StarterAuth.Issuer,
            Audience = ChallengeAudience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.UtcDateTime.Add(Lifetime),
            SigningCredentials = _credentials,
            Claims = new Dictionary<string, object>
            {
                [StarterClaims.Sub] = userId.ToString(),
            },
        };

        return new MintedChallenge(Handler.CreateToken(descriptor), (int)Lifetime.TotalSeconds);
    }

    /// <summary>
    /// Validates a challenge token (audience, expiry, signature) and returns
    /// the subject user id, or null when the token is invalid.
    /// </summary>
    public async Task<Guid?> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await Handler.ValidateTokenAsync(token, _validation);
        if (!result.IsValid)
        {
            return null;
        }

        return result.Claims.TryGetValue(StarterClaims.Sub, out var subject)
            && subject is string subjectValue
            && Guid.TryParse(subjectValue, out var userId)
            ? userId
            : null;
    }
}
