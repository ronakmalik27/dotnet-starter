using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Starter.Identity.Sso;

/// <summary>
/// The per-tenant-issuer generalization of <c>GoogleIdTokenValidator</c>: validates
/// the id_token from the code exchange against the CONFIGURED issuer's published
/// JWKS with the standard Microsoft.IdentityModel handler - signature (RS256 only),
/// issuer, audience, lifetime - then the nonce, then email_verified. Every one of
/// these checks is load-bearing (sso-and-scim.md section 4.2); returns null for
/// anything invalid, and the caller answers one generic failure for all of them.
/// <para>
/// The <c>ValidIssuer</c> is the tenant's CONFIGURED issuer (not the discovery
/// document's), so the token is pinned to THIS tenant's IdP exactly - a token whose
/// <c>iss</c> differs is rejected before it can be matched to any account.
/// </para>
/// </summary>
internal sealed class SsoIdTokenValidator(SsoOidcMetadata metadata)
{
    private static readonly JsonWebTokenHandler Handler = new();

    public async Task<SsoIdentity?> ValidateAsync(
        string idToken,
        string issuer,
        string clientId,
        string expectedNonce,
        CancellationToken cancellationToken)
    {
        var result = await ValidateOnceAsync(idToken, issuer, clientId, cancellationToken);
        if (result is { IsValid: false, Exception: SecurityTokenSignatureKeyNotFoundException })
        {
            // Key rotation: the token is signed by a key newer than the cached JWKS.
            // Refetch once and retry - the recovery the JwtBearer middleware performs.
            metadata.RequestRefresh(issuer);
            result = await ValidateOnceAsync(idToken, issuer, clientId, cancellationToken);
        }

        if (!result.IsValid)
        {
            return null;
        }

        if (!result.Claims.TryGetValue("nonce", out var nonce)
            || !string.Equals(nonce as string, expectedNonce, StringComparison.Ordinal))
        {
            // Replay defense: the id_token's nonce must echo the one bound into the
            // authorize request and stored in the state record.
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

        return new SsoIdentity(subject, emailAddress, EmailVerified(result.Claims));
    }

    private async Task<TokenValidationResult> ValidateOnceAsync(
        string idToken,
        string issuer,
        string clientId,
        CancellationToken cancellationToken)
    {
        var configuration = await metadata.GetAsync(issuer, cancellationToken);
        return await Handler.ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            // Pin to the tenant's CONFIGURED issuer and client id, not whatever the
            // discovery document happens to say.
            ValidIssuer = issuer,
            ValidAudience = clientId,
            IssuerSigningKeys = configuration.SigningKeys,
            // Pinning RS256 closes alg confusion (including alg=none) before the
            // signature is checked; enterprise IdPs (Okta, Entra, Auth0) sign with it.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
        });
    }

    /// <summary>
    /// Serialized as a JSON bool by most IdPs; tolerate the string form some emit.
    /// Anything else counts as unverified - the fail-closed reading (linking keys on
    /// a VERIFIED email).
    /// </summary>
    private static bool EmailVerified(IDictionary<string, object> claims) =>
        claims.TryGetValue("email_verified", out var value) && value switch
        {
            bool verified => verified,
            string text => bool.TryParse(text, out var parsed) && parsed,
            _ => false,
        };
}
