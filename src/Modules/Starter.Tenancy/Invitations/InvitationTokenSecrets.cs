using System.Security.Cryptography;
using System.Text;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// Raw material for tenancy.invitations tokens: 256-bit random - the same
/// strength as identity's one-time tokens - transported as unpadded base64url,
/// stored only as a SHA-256 hex digest. The 2^256 preimage space needs no
/// stretching, and the deterministic hash is what makes the accept lookup
/// (keyed on token_hash) indexable. Mirrors OneTimeTokenSecrets in Identity;
/// duplicated rather than shared because a module exports no helper types.
/// </summary>
internal static class InvitationTokenSecrets
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
