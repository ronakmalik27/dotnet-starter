using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Starter.Api.Auth;

/// <summary>
/// Reads and hashes a service-account API key off the request
/// (service-accounts.md sections 2, 3). A key is presented either as
/// <c>Authorization: Bearer sk_...</c> - the <c>sk_</c> prefix is how the auth
/// layer tells an API key from a JWT - or as an <c>X-Api-Key</c> header. The raw
/// key is hashed to the SHA-256 hex digest the module resolves on; this is the
/// Api-layer copy of the hashing idiom (the module's <c>ApiKeySecrets</c> is
/// internal and unreachable here, so the deterministic hash is duplicated exactly
/// as <c>OneTimeTokenSecrets</c> / <c>InvitationTokenSecrets</c> already are). The
/// raw key is never logged or persisted - only its hash leaves this layer.
/// </summary>
internal static class ApiKeyCredential
{
    /// <summary>The raw-key scheme prefix (also what secret scanners match on).</summary>
    public const string RawKeyPrefix = "sk_";

    /// <summary>The alternative header carrying a raw key.</summary>
    public const string HeaderName = "X-Api-Key";

    private const string BearerPrefix = "Bearer ";

    /// <summary>
    /// True when the request presents an API key: an <c>X-Api-Key</c> header, or an
    /// <c>Authorization: Bearer sk_...</c> value. The forwarding policy scheme uses
    /// this to route the request to the ApiKey scheme; everything else goes to JWT.
    /// </summary>
    public static bool IsApiKeyRequest(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request.Headers.TryGetValue(HeaderName, out var apiKeyValues)
            && !string.IsNullOrWhiteSpace(apiKeyValues.ToString()))
        {
            return true;
        }

        var authorization = context.Request.Headers.Authorization.ToString();
        return authorization.StartsWith(BearerPrefix + RawKeyPrefix, StringComparison.Ordinal);
    }

    /// <summary>
    /// Extracts the raw key from the request, preferring <c>X-Api-Key</c>. Returns
    /// false when neither carrier holds a key; the handler then returns NoResult.
    /// </summary>
    public static bool TryRead(HttpRequest request, out string rawKey)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Headers.TryGetValue(HeaderName, out var apiKeyValues))
        {
            var value = apiKeyValues.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                rawKey = value;
                return true;
            }
        }

        var authorization = request.Headers.Authorization.ToString();
        if (authorization.StartsWith(BearerPrefix + RawKeyPrefix, StringComparison.Ordinal))
        {
            rawKey = authorization[BearerPrefix.Length..];
            return true;
        }

        rawKey = string.Empty;
        return false;
    }

    /// <summary>The SHA-256 hex digest of the raw key: the module's tenant-less lookup value.</summary>
    public static string Hash(string rawKey) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey)));
}
