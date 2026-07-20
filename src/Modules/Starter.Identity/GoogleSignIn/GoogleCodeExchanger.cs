using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// The server side of the SPA/mobile code-exchange pattern (doc 08 2.1):
/// the client ran the authorization request (with PKCE and nonce) and
/// hands us the authorization code; we redeem it at the issuer's token
/// endpoint with the confidential client secret plus the client's
/// code_verifier, so Google enforces PKCE (doc 10 4.5 - code flow only,
/// never implicit). Returns the raw ID token, or null for any refusal -
/// a non-success status, a network fault, a request timeout, or a
/// malformed/non-JSON body: which field Google disliked is logged by
/// Google, not leaked to our caller, and the handler maps every case to
/// the same generic Unauthorized (CodeRabbit review, PR #264).
/// </summary>
internal sealed class GoogleCodeExchanger(
    HttpClient httpClient,
    GoogleOidcMetadata metadata,
    IOptions<GoogleOidcOptions> options)
{
    public async Task<string?> ExchangeAsync(
        string code,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await metadata.GetAsync(cancellationToken);

            using var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["code_verifier"] = codeVerifier,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = options.Value.ClientId!,
                ["client_secret"] = options.Value.ClientSecret!,
            });
            using var response = await httpClient.PostAsync(
                new Uri(configuration.TokenEndpoint), body, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var content = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var json = await JsonDocument.ParseAsync(content, cancellationToken: cancellationToken);
            return json.RootElement.TryGetProperty("id_token", out var idToken)
                ? idToken.GetString()
                : null;
        }
        catch (Exception exception) when (IsExchangeFailure(exception, cancellationToken))
        {
            // Network fault (DNS, connection refused, TLS), a timeout
            // (HttpClient's own or the discovery ConfigurationManager's),
            // or a body that is not the JSON Google promises: all of
            // these are exchange failures like a non-success status,
            // never an unhandled exception surfacing past the handler.
            return null;
        }
    }

    /// <summary>
    /// True for a genuine exchange failure; false for a caller-initiated
    /// cancellation (client disconnect), which must propagate so ASP.NET
    /// handles it as request-aborted rather than being swallowed as a
    /// failed sign-in. The discovery/JWKS ConfigurationManager wraps its
    /// own network faults in an InvalidOperationException (IDX20803)
    /// around the real HttpRequestException/IOException, so the network
    /// check walks the inner-exception chain rather than matching the
    /// outermost type alone (verified against the actual wrapped shape
    /// in GoogleSignIn_NetworkFailureTalkingToTheIssuer_Is401_
    /// NotAnUnhandledException).
    /// </summary>
    private static bool IsExchangeFailure(Exception exception, CancellationToken cancellationToken) =>
        exception switch
        {
            HttpRequestException => true,
            JsonException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            InvalidOperationException when IsNetworkFault(exception.InnerException) => true,
            _ => false,
        };

    private static bool IsNetworkFault(Exception? exception) => exception switch
    {
        null => false,
        HttpRequestException or IOException => true,
        _ => IsNetworkFault(exception.InnerException),
    };
}
