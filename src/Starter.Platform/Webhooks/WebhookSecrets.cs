using System.Security.Cryptography;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Raw material for a webhook signing secret (webhooks.md section 5): 256-bit random,
/// carried as <c>whsec_&lt;unpadded base64url&gt;</c>. The <c>whsec_</c> prefix is
/// deliberate - it is what secret scanners (GitHub secret scanning, gitleaks) match on,
/// so a leaked secret is detectable (the Stripe scheme). Unlike an API key (hashed,
/// never recovered), a signing secret must be usable to HMAC-sign every delivery, so it
/// is stored ENCRYPTED (see <c>WebhookSecretProtector</c>), not hashed. The raw secret is
/// returned ONCE at register and rotate and never persisted in the clear.
/// </summary>
internal static class WebhookSecrets
{
    private const int SecretBytes = 32;

    /// <summary>The raw-secret scheme prefix secret scanners match on.</summary>
    public const string RawSecretPrefix = "whsec_";

    /// <summary>The number of raw-secret characters kept in clear for display.</summary>
    private const int PrefixLength = 12;

    /// <summary>Mints a fresh raw secret: <c>whsec_&lt;base64url(32 random bytes)&gt;</c>. Never persisted in the clear.</summary>
    public static string NewSecret() =>
        RawSecretPrefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(SecretBytes));

    /// <summary>
    /// The first several characters of the raw secret (for example <c>whsec_ab12cd</c>),
    /// stored in clear for display so an admin can tell secrets apart without the secret
    /// ever being retrievable.
    /// </summary>
    public static string Prefix(string rawSecret)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawSecret);

        return rawSecret.Length <= PrefixLength ? rawSecret : rawSecret[..PrefixLength];
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
