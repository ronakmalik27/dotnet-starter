using System.Collections.Concurrent;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Starter.Identity.Sso;

/// <summary>
/// The per-tenant-issuer generalization of <c>GoogleOidcMetadata</c>: a
/// <see cref="ConfigurationManager{T}"/> per configured issuer (the standard
/// Microsoft.IdentityModel component the ASP.NET OIDC middleware uses underneath),
/// each caching that issuer's discovery document and JWKS with automatic refresh,
/// so per-callback resolution costs no network round trip after warm-up. Singleton:
/// the managers cache across requests, keyed by issuer.
/// <para>
/// <see cref="HttpDocumentRetriever.RequireHttps"/> follows the issuer scheme -
/// production issuers are always https (the admin save endpoint refuses any other),
/// and the plain-http escape hatch exists ONLY for the integration suite's loopback
/// fake IdP, exactly as the Google metadata does. A free-text per-tenant issuer
/// cannot smuggle a plain-http authority past the save-time https check, so this
/// switch never relaxes a real tenant's fetch.
/// </para>
/// </summary>
internal sealed class SsoOidcMetadata(IHttpClientFactory httpClientFactory)
{
    /// <summary>The named HttpClient discovery and JWKS requests ride.</summary>
    public const string HttpClientName = "sso-oidc-metadata";

    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers =
        new(StringComparer.Ordinal);

    /// <summary>The issuer's cached discovery document and signing keys.</summary>
    public Task<OpenIdConnectConfiguration> GetAsync(string issuer, CancellationToken cancellationToken) =>
        ManagerFor(issuer).GetConfigurationAsync(cancellationToken);

    /// <summary>
    /// Forces a metadata refetch on the next read for one issuer - the JWKS rotation
    /// path (a token signed by a key minted after the cached document).
    /// </summary>
    public void RequestRefresh(string issuer)
    {
        if (_managers.TryGetValue(Normalize(issuer), out var manager))
        {
            manager.RequestRefresh();
        }
    }

    private ConfigurationManager<OpenIdConnectConfiguration> ManagerFor(string issuer) =>
        _managers.GetOrAdd(Normalize(issuer), authority => new ConfigurationManager<OpenIdConnectConfiguration>(
            authority + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(httpClientFactory.CreateClient(HttpClientName))
            {
                RequireHttps = authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
            }));

    private static string Normalize(string issuer) => issuer.TrimEnd('/');
}
