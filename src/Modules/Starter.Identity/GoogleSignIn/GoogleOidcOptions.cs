namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// Google OIDC settings (doc 10 4.5), bound from the Auth:Google section.
/// The client secret lives only in its designated homes (doc 10 section 9:
/// dotnet user-secrets locally, Key Vault in production) - never in a
/// committed config file. A host without the section boots fine and
/// answers 501 on the exchange endpoint, mirroring how the app degrades
/// without other optional wiring.
/// </summary>
internal sealed class GoogleOidcOptions
{
    public const string SectionName = "Auth:Google";

    /// <summary>The OAuth client id the SPA/mobile clients also use.</summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The web-client secret for the server-side code exchange (Google
    /// requires it on the token endpoint for web application clients).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// The OIDC issuer whose discovery document drives the token exchange
    /// and ID-token validation. Production is always Google; the override
    /// exists for the integration suite's fake issuer (doc 12: the flow is
    /// tested end-to-end against a real code exchange).
    /// </summary>
    public string Authority { get; set; } = "https://accounts.google.com";

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
