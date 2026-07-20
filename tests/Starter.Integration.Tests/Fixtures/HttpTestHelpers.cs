using System.Text.Json;
using Starter.Platform.Notifications;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>Small helpers shared by the integration tests.</summary>
internal static class HttpTestHelpers
{
    private static readonly char[] TokenTerminators = [' ', '\r', '\n', '\t'];

    /// <summary>Reads a JSON response body into a document.</summary>
    public static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonDocument.Parse(body);
    }

    /// <summary>
    /// Returns the value of a Set-Cookie cookie by name, or null when the
    /// response set no such cookie. Parses the raw header so a Secure cookie
    /// is readable even over the test host's http scheme.
    /// </summary>
    public static string? ReadSetCookie(HttpResponseMessage response, string cookieName)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            return null;
        }

        var prefix = cookieName + "=";
        foreach (var header in setCookies)
        {
            if (!header.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            var afterName = header[prefix.Length..];
            var end = afterName.IndexOf(';', StringComparison.Ordinal);
            return end < 0 ? afterName : afterName[..end];
        }

        return null;
    }

    /// <summary>
    /// Pulls the raw verification token out of a captured email by reading
    /// the token query parameter from the verify link in the text body.
    /// </summary>
    public static string ExtractVerificationToken(EmailMessage email)
    {
        ArgumentNullException.ThrowIfNull(email);

        const string marker = "token=";
        var body = email.TextBody;
        var start = body.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException("The verification email has no token parameter.");
        }

        var rest = body[(start + marker.Length)..];
        var end = rest.IndexOfAny(TokenTerminators);
        var encoded = end < 0 ? rest : rest[..end];
        return Uri.UnescapeDataString(encoded);
    }
}
