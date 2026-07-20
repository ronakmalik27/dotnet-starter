using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// Validates the ID token from the code exchange with the standard
/// Microsoft.IdentityModel handler against the issuer's published JWKS:
/// signature (RS256 only), issuer, audience (our client id), lifetime -
/// and then the nonce, which must echo the value the client bound into
/// its authorization request (doc 10 4.5: code flow + PKCE + nonce).
/// Returns null for anything invalid; the caller answers one generic
/// failure for all of them.
/// </summary>
internal sealed class GoogleIdTokenValidator(
    GoogleOidcMetadata metadata,
    IOptions<GoogleOidcOptions> options)
{
    private static readonly JsonWebTokenHandler Handler = new();

    public async Task<GoogleIdentity?> ValidateAsync(
        string idToken,
        string expectedNonce,
        CancellationToken cancellationToken)
    {
        var result = await ValidateOnceAsync(idToken, cancellationToken);
        if (result is { IsValid: false, Exception: SecurityTokenSignatureKeyNotFoundException })
        {
            // Key rotation: the token is signed by a key newer than our
            // cached JWKS. Refetch once and retry - the same recovery the
            // JwtBearer middleware performs.
            metadata.RequestRefresh();
            result = await ValidateOnceAsync(idToken, cancellationToken);
        }

        if (!result.IsValid)
        {
            return null;
        }

        if (!result.Claims.TryGetValue("nonce", out var nonce)
            || !string.Equals(nonce as string, expectedNonce, StringComparison.Ordinal))
        {
            return null;
        }

        if (!result.Claims.TryGetValue("sub", out var sub)
            || sub is not string subject
            || string.IsNullOrEmpty(subject)
            || !result.Claims.TryGetValue("email", out var email)
            || email is not string emailAddress
            || string.IsNullOrEmpty(emailAddress))
        {
            return null;
        }

        return new GoogleIdentity(subject, emailAddress, EmailVerified(result.Claims));
    }

    private async Task<TokenValidationResult> ValidateOnceAsync(
        string idToken,
        CancellationToken cancellationToken)
    {
        var configuration = await metadata.GetAsync(cancellationToken);
        return await Handler.ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = configuration.Issuer,
            ValidAudience = options.Value.ClientId,
            IssuerSigningKeys = configuration.SigningKeys,
            // RS256 is what Google signs with (its discovery document
            // advertises only RS256); pinning it closes alg confusion,
            // including alg=none, before signature checking.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
        });
    }

    /// <summary>
    /// Google serializes email_verified as a JSON bool; tolerate the
    /// string form some issuers emit. Anything else counts as unverified -
    /// the fail-closed reading (SRS 5.3 keys linking on VERIFIED email).
    /// </summary>
    private static bool EmailVerified(IDictionary<string, object> claims) =>
        claims.TryGetValue("email_verified", out var value) && value switch
        {
            bool verified => verified,
            string text => bool.TryParse(text, out var parsed) && parsed,
            _ => false,
        };
}
