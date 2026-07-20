using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Tokens;

/// <summary>
/// Raw material for one_time_tokens rows (doc 10 4.4): 256-bit random -
/// double the 128-bit floor the security design requires, matching the
/// refresh-token strength - transported as unpadded base64url, stored only
/// as a SHA-256 hex digest. The same no-KDF rationale as RefreshTokens
/// applies: 2^256 preimage space needs no stretching, and a deterministic
/// hash is what makes the redemption lookup indexable.
/// </summary>
internal static class OneTimeTokenSecrets
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
