using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Tokens;

/// <summary>
/// Refresh-token material (doc 10 4.2): 256-bit random, transported as
/// unpadded base64url, stored only as a SHA-256 hex digest. SHA-256
/// without salt or stretching is the industry norm for high-entropy
/// tokens (GitHub, Stripe API keys): 2^256 preimage space needs no KDF,
/// and a deterministic hash is what makes the indexed lookup possible.
/// </summary>
internal static class RefreshTokens
{
    private const int TokenBytes = 32;

    public static string NewToken() =>
        Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenBytes));

    public static string Hash(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
