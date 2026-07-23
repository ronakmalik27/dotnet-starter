using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Sso;

/// <summary>
/// Random material for the SSO authorization request (sso-and-scim.md section 4.1):
/// the CSRF <c>state</c>, the replay <c>nonce</c>, and the S256 PKCE
/// <c>code_verifier</c> / <c>code_challenge</c>. Every value is 256-bit random
/// transported as unpadded base64url; a base64url of 32 bytes is 43 characters, a
/// valid PKCE code_verifier (43..128 unreserved chars). The <c>state</c> is stored
/// server-side only as a SHA-256 hex digest (the one_time_tokens / refresh_hash
/// rule), so possession of the raw value is what proves the callback.
/// </summary>
internal static class SsoSecrets
{
    private const int TokenBytes = 32;

    /// <summary>A fresh 256-bit random token as unpadded base64url (state, nonce, PKCE verifier).</summary>
    public static string NewToken() => Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenBytes));

    /// <summary>The SHA-256 hex digest of a token, for the server-side state lookup.</summary>
    public static string Hash(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }

    /// <summary>The S256 PKCE code_challenge for a verifier: base64url(SHA-256(ASCII(verifier))).</summary>
    public static string PkceChallenge(string codeVerifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(codeVerifier);
        return Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
