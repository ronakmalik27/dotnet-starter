using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// The issuer's discovery document and JWKS, via the standard
/// Microsoft.IdentityModel ConfigurationManager - the same component the
/// ASP.NET OIDC middleware uses underneath ("standard
/// middleware"; the redirect-based middleware itself does not fit the
/// POST /auth/google code-exchange shape). Singleton: the manager
/// caches the document and keys with automatic refresh, so per-request
/// resolution costs no network round trip.
/// </summary>
internal sealed class GoogleOidcMetadata
{
    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _manager;

    public GoogleOidcMetadata(IOptions<GoogleOidcOptions> options, IHttpClientFactory httpClientFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        if (!options.Value.IsConfigured)
        {
            return;
        }

        var authority = options.Value.Authority.TrimEnd('/');
        _manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            authority + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(httpClientFactory.CreateClient(HttpClientName))
            {
                // Google is always https; a plain-http authority exists
                // only for the integration suite's loopback fake issuer
                // (the same switch the OIDC middleware exposes as
                // RequireHttpsMetadata).
                RequireHttps = authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
            });
    }

    /// <summary>The named HttpClient discovery and JWKS requests ride.</summary>
    public const string HttpClientName = "google-oidc-metadata";

    /// <summary>Throws when the section is not configured; callers gate on IsConfigured first.</summary>
    public Task<OpenIdConnectConfiguration> GetAsync(CancellationToken cancellationToken) =>
        _manager?.GetConfigurationAsync(cancellationToken)
        ?? throw new InvalidOperationException(
            "Google OIDC is not configured (Auth:Google); the handler must gate on IsConfigured.");

    /// <summary>
    /// Forces a metadata refetch on the next read - the JWKS rotation path
    /// (a token signed by a key minted after our cached document).
    /// </summary>
    public void RequestRefresh() => _manager?.RequestRefresh();
}
