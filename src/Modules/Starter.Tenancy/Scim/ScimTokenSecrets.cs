using System.Security.Cryptography;
using System.Text;

namespace Starter.Tenancy.Scim;

/// <summary>
/// Raw material for a SCIM bearer token (sso-and-scim.md section 5): 256-bit random -
/// the same strength as a service-account API key - carried as
/// <c>scim_&lt;unpadded base64url&gt;</c> and stored only as a SHA-256 hex digest.
/// The 2^256 preimage space needs no stretching (the "GitHub / Stripe API key"
/// rationale), and the deterministic hash is what makes the tenant-less resolve
/// lookup (keyed on token_hash) indexable. The <c>scim_</c> prefix is deliberate: it
/// is what secret scanners (GitHub secret scanning, gitleaks) match on, so a leaked
/// token is detectable, and it is how the authentication layer tells a SCIM token
/// from a service-account key or a JWT. Mirrors <c>ApiKeySecrets</c>; duplicated
/// rather than shared because a module exports no helper types.
/// </summary>
internal static class ScimTokenSecrets
{
    private const int TokenBytes = 32;

    /// <summary>The raw-token scheme prefix secret scanners and the auth layer match on.</summary>
    public const string RawTokenPrefix = "scim_";

    /// <summary>The number of raw-token characters kept in clear for display.</summary>
    private const int PrefixLength = 11;

    /// <summary>Mints a fresh raw token: <c>scim_&lt;base64url(32 random bytes)&gt;</c>. Never persisted.</summary>
    public static string NewToken() =>
        RawTokenPrefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenBytes));

    /// <summary>The SHA-256 hex digest of the raw token: the persisted lookup value.</summary>
    public static string Hash(string rawToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawToken);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
    }

    /// <summary>
    /// The first several characters of the raw token (for example <c>scim_ab12cd</c>),
    /// stored in clear for display so an admin can tell tokens apart in a list without
    /// the secret ever being retrievable.
    /// </summary>
    public static string Prefix(string rawToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawToken);

        return rawToken.Length <= PrefixLength ? rawToken : rawToken[..PrefixLength];
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
