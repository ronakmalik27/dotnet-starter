using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// A loopback fake OIDC identity provider for the SSO suite (sso-and-scim.md
/// section 9), the GoogleOidcMetadata loopback pattern generalized: a real Kestrel
/// server on http://127.0.0.1:{port} serving a discovery document, a JWKS, and a
/// token endpoint, so the host-under-test's real outbound HttpClient (metadata +
/// code exchange) reaches it. The plain-http loopback issuer is exactly the escape
/// hatch RequireHttps=false permits for a local test IdP.
/// <para>
/// The JWT is hand-crafted (RS256 over RSA) with System.Security.Cryptography, so
/// the fixture depends on no token library and the test controls every claim - the
/// negative cases stage a token with the wrong iss, wrong aud, a bad signature (a
/// key NOT in the JWKS), an expired lifetime, a wrong nonce, or
/// email_verified=false, and assert each is rejected. <see cref="NextIdToken"/> is
/// what the token endpoint returns for the next exchange; the test stages it after
/// reading the nonce from the authorize redirect.
/// </para>
/// </summary>
internal sealed class FakeOidcProvider : IAsyncDisposable
{
    private const string Kid = "starter-fake-oidc-key-1";

    private static readonly string[] ResponseTypes = ["code"];
    private static readonly string[] SubjectTypes = ["public"];
    private static readonly string[] SigningAlgs = ["RS256"];

    private readonly WebApplication _app;
    private readonly RSA _signingKey = RSA.Create(2048);

    // A second key that is NEVER published in the JWKS: the bad-signature case signs
    // with it, so verification against the published key fails.
    private readonly RSA _wrongKey = RSA.Create(2048);

    private FakeOidcProvider(WebApplication app) => _app = app;

    /// <summary>The issuer base URL (http loopback), set once the server has bound its port.</summary>
    public string Issuer { get; private set; } = string.Empty;

    /// <summary>The id_token the token endpoint returns for the next code exchange.</summary>
    public string NextIdToken { get; set; } = string.Empty;

    public static async Task<FakeOidcProvider> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var provider = new FakeOidcProvider(app);

        app.MapGet("/.well-known/openid-configuration", (HttpContext http) =>
        {
            var issuer = provider.Issuer;
            return Results.Json(new Dictionary<string, object>
            {
                ["issuer"] = issuer,
                ["authorization_endpoint"] = issuer + "/authorize",
                ["token_endpoint"] = issuer + "/token",
                ["jwks_uri"] = issuer + "/jwks",
                ["response_types_supported"] = ResponseTypes,
                ["subject_types_supported"] = SubjectTypes,
                ["id_token_signing_alg_values_supported"] = SigningAlgs,
            });
        });

        app.MapGet("/jwks", () => Results.Json(provider.Jwks()));

        // Any code exchanges for the staged id_token; the fake IdP does not track
        // codes (the suite drives one exchange per flow).
        app.MapPost("/token", () => Results.Json(new Dictionary<string, object>
        {
            ["id_token"] = provider.NextIdToken,
            ["access_token"] = "fake-access-token",
            ["token_type"] = "Bearer",
            ["expires_in"] = 3600,
        }));

        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!
            .Addresses.First();
        provider.Issuer = address.TrimEnd('/');
        return provider;
    }

    /// <summary>
    /// Builds a signed id_token. Defaults produce a fully-valid token; each optional
    /// override drives one negative case. <paramref name="signWithWrongKey"/> signs
    /// with a key absent from the JWKS (the bad-signature case).
    /// </summary>
    public string CreateIdToken(
        string subject,
        string email,
        string nonce,
        bool emailVerified = true,
        string? issuer = null,
        string? audience = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expires = null,
        bool signWithWrongKey = false)
    {
        var now = DateTimeOffset.UtcNow;
        var nbf = notBefore ?? now.AddMinutes(-1);
        var exp = expires ?? now.AddMinutes(5);

        var header = new Dictionary<string, object>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["kid"] = Kid,
        };
        var payload = new Dictionary<string, object>
        {
            ["iss"] = issuer ?? Issuer,
            ["aud"] = audience ?? DefaultAudience,
            ["sub"] = subject,
            ["email"] = email,
            ["email_verified"] = emailVerified,
            ["nonce"] = nonce,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = nbf.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        var signingInput = Base64UrlEncode(Serialize(header)) + "." + Base64UrlEncode(Serialize(payload));
        var key = signWithWrongKey ? _wrongKey : _signingKey;
        var signature = key.SignData(
            Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64UrlEncode(signature);
    }

    /// <summary>The default client id the suite configures the tenant with (the id_token audience).</summary>
    public const string DefaultAudience = "starter-sso-client";

    private Dictionary<string, object> Jwks()
    {
        var parameters = _signingKey.ExportParameters(includePrivateParameters: false);
        return new Dictionary<string, object>
        {
            ["keys"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["kty"] = "RSA",
                    ["use"] = "sig",
                    ["alg"] = "RS256",
                    ["kid"] = Kid,
                    ["n"] = Base64UrlEncode(parameters.Modulus!),
                    ["e"] = Base64UrlEncode(parameters.Exponent!),
                },
            },
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _signingKey.Dispose();
        _wrongKey.Dispose();
    }

    private static byte[] Serialize(Dictionary<string, object> value) =>
        JsonSerializer.SerializeToUtf8Bytes(value);

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
