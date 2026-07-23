using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Starter.Api.Auth;

/// <summary>
/// Reads and hashes a SCIM bearer off the request (sso-and-scim.md section 5). A
/// SCIM token is presented as <c>Authorization: Bearer scim_...</c> - the
/// <c>scim_</c> prefix is how the auth layer tells a SCIM token from a JWT or a
/// service-account key. The raw token is hashed to the SHA-256 hex digest the module
/// resolves on; this is the Api-layer copy of the hashing idiom (the module's
/// <c>ScimTokenSecrets</c> is internal and unreachable here, so the deterministic
/// hash is duplicated exactly as <c>ApiKeyCredential</c> already is). The raw token
/// is never logged or persisted - only its hash leaves this layer.
/// </summary>
internal static class ScimCredential
{
    /// <summary>The raw-token scheme prefix (also what secret scanners match on).</summary>
    public const string RawTokenPrefix = "scim_";

    private const string BearerPrefix = "Bearer ";

    /// <summary>
    /// True when the request should be routed to the Scim scheme: it presents an
    /// <c>Authorization: Bearer scim_...</c> value AND its path is under
    /// <see cref="ScimAuthenticationDefaults.PathPrefix"/>. BOTH conditions are
    /// load-bearing (CRITICAL rule 1): a <c>scim_</c> bearer on any other path is NOT
    /// routed here, so it falls through to JWT and gets a 401 - a SCIM token never
    /// authenticates a non-SCIM route.
    /// </summary>
    public static bool IsScimRequest(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Path.StartsWithSegments(
            ScimAuthenticationDefaults.PathPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var authorization = context.Request.Headers.Authorization.ToString();
        return authorization.StartsWith(BearerPrefix + RawTokenPrefix, StringComparison.Ordinal);
    }

    /// <summary>
    /// Extracts the raw <c>scim_</c> token from the Authorization header. Returns false
    /// when it is absent; the handler then returns NoResult.
    /// </summary>
    public static bool TryRead(HttpRequest request, out string rawToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var authorization = request.Headers.Authorization.ToString();
        if (authorization.StartsWith(BearerPrefix + RawTokenPrefix, StringComparison.Ordinal))
        {
            rawToken = authorization[BearerPrefix.Length..];
            return true;
        }

        rawToken = string.Empty;
        return false;
    }

    /// <summary>The SHA-256 hex digest of the raw token: the module's tenant-less lookup value.</summary>
    public static string Hash(string rawToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
}
