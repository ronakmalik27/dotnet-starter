using System.Security.Cryptography;
using System.Text;

namespace Starter.Tenancy.ServiceAccounts;

/// <summary>
/// Raw material for a service-account API key (service-accounts.md section 2):
/// 256-bit random - the same strength as identity's one-time tokens and the
/// invitation token - carried as <c>sk_&lt;unpadded base64url&gt;</c> and stored
/// only as a SHA-256 hex digest. The 2^256 preimage space needs no stretching
/// (the "GitHub / Stripe API key" rationale the refresh-token helper already
/// cites), and the deterministic hash is what makes the tenant-less resolve
/// lookup (keyed on key_hash) indexable. The <c>sk_</c> prefix is deliberate: it
/// is what secret scanners (GitHub secret scanning, gitleaks) match on, so a
/// leaked key is detectable, and it is how the authentication layer tells an API
/// key from a JWT. Mirrors <c>InvitationTokenSecrets</c> / <c>OneTimeTokenSecrets</c>;
/// duplicated rather than shared because a module exports no helper types.
/// </summary>
internal static class ApiKeySecrets
{
    private const int KeyBytes = 32;

    /// <summary>The raw-key scheme prefix secret scanners and the auth layer match on.</summary>
    public const string RawKeyPrefix = "sk_";

    /// <summary>The number of raw-key characters kept in clear for display.</summary>
    private const int PrefixLength = 9;

    /// <summary>Mints a fresh raw key: <c>sk_&lt;base64url(32 random bytes)&gt;</c>. Never persisted.</summary>
    public static string NewKey() =>
        RawKeyPrefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(KeyBytes));

    /// <summary>The SHA-256 hex digest of the raw key: the persisted lookup value.</summary>
    public static string Hash(string rawKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawKey);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey)));
    }

    /// <summary>
    /// The first several characters of the raw key (for example <c>sk_ab12cd</c>),
    /// stored in clear for display so an admin can tell keys apart in a list
    /// without the secret ever being retrievable.
    /// </summary>
    public static string Prefix(string rawKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawKey);

        return rawKey.Length <= PrefixLength ? rawKey : rawKey[..PrefixLength];
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
