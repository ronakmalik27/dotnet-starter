using System.IO;
using System.Text.Json;

namespace Starter.Identity.Sso;

/// <summary>
/// The per-tenant-issuer generalization of <c>GoogleCodeExchanger</c>: redeems the
/// authorization code at the configured issuer's token endpoint (from its discovery
/// document) with the confidential client id + client secret + the PKCE
/// code_verifier, over the issuer's own transport (https for a real tenant; the
/// loopback fake IdP for the suite). Returns the raw id_token, or null for any
/// refusal - a non-success status, a network fault, a timeout, or a malformed body:
/// which field the IdP disliked is not leaked to the caller, and the handler maps
/// every case to the same generic failure.
/// </summary>
internal sealed class SsoCodeExchanger(HttpClient httpClient, SsoOidcMetadata metadata)
{
    public async Task<string?> ExchangeAsync(
        string issuer,
        string clientId,
        string clientSecret,
        string code,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await metadata.GetAsync(issuer, cancellationToken);

            using var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["code_verifier"] = codeVerifier,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
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
            // A network fault, a timeout, or a non-JSON body are all exchange
            // failures like a non-success status, never an unhandled exception past
            // the handler. A caller-initiated cancellation propagates.
            return null;
        }
    }

    private static bool IsExchangeFailure(Exception exception, CancellationToken cancellationToken) =>
        exception switch
        {
            HttpRequestException => true,
            JsonException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            // The discovery/JWKS ConfigurationManager wraps its own network faults in
            // an InvalidOperationException around the real HttpRequestException/
            // IOException, so walk the inner chain (the Google exchanger's shape).
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
