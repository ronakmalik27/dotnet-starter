using System.Security.Cryptography;
using System.Text;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The delivery signature (webhooks.md section 5): <c>HMAC-SHA256(secret,
/// "{timestamp}.{body}")</c>, sent as the <c>X-Starter-Signature: t=&lt;unix&gt;,v1=&lt;hex&gt;</c>
/// header (the Stripe scheme). The receiver recomputes and constant-time compares, and
/// rejects a stale timestamp; the timestamp is signed (not just sent) so it cannot be
/// altered. The raw secret is never logged and never leaves this computation.
/// </summary>
internal static class WebhookSigner
{
    /// <summary>The signature header name.</summary>
    public const string HeaderName = "X-Starter-Signature";

    /// <summary>
    /// The lowercase-hex HMAC-SHA256 over <c>"{unixSeconds}.{body}"</c> keyed by the raw
    /// secret. Deterministic for a given (secret, timestamp, body).
    /// </summary>
    public static string ComputeSignature(string secret, long unixSeconds, string body)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        ArgumentNullException.ThrowIfNull(body);

        var signingInput = Encoding.UTF8.GetBytes($"{unixSeconds}.{body}");
        var key = Encoding.UTF8.GetBytes(secret);
        var hash = HMACSHA256.HashData(key, signingInput);
        return Convert.ToHexStringLower(hash);
    }

    /// <summary>The full <c>t=&lt;unix&gt;,v1=&lt;hex&gt;</c> header value for a body and timestamp.</summary>
    public static string BuildHeader(string secret, long unixSeconds, string body) =>
        $"t={unixSeconds},v1={ComputeSignature(secret, unixSeconds, body)}";
}
