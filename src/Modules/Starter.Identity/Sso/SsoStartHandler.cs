using System.Text;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Sso;

/// <summary>
/// SP-initiated SSO initiation (sso-and-scim.md section 4.1): resolve the tenant
/// from a <c>?email</c> domain-claim (exact, case-insensitive, verified) or an
/// explicit <c>?tenantId</c>, load its ENABLED SSO config, and build the IdP
/// authorize URL with a random state (CSRF), nonce (replay), and an S256 PKCE
/// code_challenge (code-interception defense). A single-use server-side state
/// record is stored - keyed by the state hash - holding the resolved tenant, the
/// nonce, the code_verifier, the redirect_uri, and the caller's user id when /start
/// ran authenticated. Returns the authorize URL to redirect to plus the raw state
/// for the CSRF cookie. Every unroutable case (no verified domain, no config,
/// disabled, IdP unreachable) is one generic failure, so a probe cannot map which
/// tenants have SSO.
/// </summary>
internal sealed class SsoStartHandler(
    ITenantSsoConfigReader configReader,
    SsoOidcMetadata metadata,
    SsoStateStore stateStore)
{
    private const string Scope = "openid email profile";

    private static readonly Error NotAvailable = new(
        ErrorKind.NotFound,
        "auth.sso_not_available",
        "Enterprise SSO is not available for this request.");

    public async Task<Result<(string AuthorizeUrl, string State)>> HandleAsync(
        string? email,
        Guid? tenantId,
        Guid? callerUserId,
        string redirectUri,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);

        // The tenant is resolved BEFORE any config read: from an explicit tenantId,
        // else from the email's domain via a VERIFIED claim. An unverified or
        // unclaimed domain resolves to nothing and does not route.
        Guid resolvedTenant;
        if (tenantId is Guid explicitTenant)
        {
            resolvedTenant = explicitTenant;
        }
        else if (TryGetDomain(email, out var domain))
        {
            var byDomain = await configReader.ResolveTenantByVerifiedDomainAsync(domain, cancellationToken);
            if (byDomain is not Guid domainTenant)
            {
                return NotAvailable;
            }

            resolvedTenant = domainTenant;
        }
        else
        {
            return NotAvailable;
        }

        var config = await configReader.GetConfigAsync(resolvedTenant, cancellationToken);
        if (config is null || !config.Enabled)
        {
            return NotAvailable;
        }

        string authorizationEndpoint;
        try
        {
            var discovery = await metadata.GetAsync(config.Issuer, cancellationToken);
            authorizationEndpoint = discovery.AuthorizationEndpoint;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The IdP's discovery document is unreachable or malformed: a generic
            // "not available", never an unhandled 500.
            return NotAvailable;
        }

        if (string.IsNullOrEmpty(authorizationEndpoint))
        {
            return NotAvailable;
        }

        var state = SsoSecrets.NewToken();
        var nonce = SsoSecrets.NewToken();
        var codeVerifier = SsoSecrets.NewToken();
        var codeChallenge = SsoSecrets.PkceChallenge(codeVerifier);

        await stateStore.StoreAsync(
            SsoSecrets.Hash(state),
            resolvedTenant,
            nonce,
            codeVerifier,
            redirectUri,
            callerUserId,
            cancellationToken);

        var authorizeUrl = BuildAuthorizeUrl(
            authorizationEndpoint, config.ClientId, redirectUri, state, nonce, codeChallenge);
        return Result.Success((authorizeUrl, state));
    }

    private static bool TryGetDomain(string? email, out string domain)
    {
        domain = string.Empty;
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        var at = email.LastIndexOf('@');
        if (at <= 0 || at == email.Length - 1)
        {
            return false;
        }

        domain = email[(at + 1)..].Trim();
        return domain.Length > 0 && domain.Contains('.', StringComparison.Ordinal);
    }

    private static string BuildAuthorizeUrl(
        string authorizationEndpoint,
        string clientId,
        string redirectUri,
        string state,
        string nonce,
        string codeChallenge)
    {
        var query = new StringBuilder();
        Append(query, "client_id", clientId);
        Append(query, "redirect_uri", redirectUri);
        Append(query, "response_type", "code");
        Append(query, "scope", Scope);
        Append(query, "state", state);
        Append(query, "nonce", nonce);
        Append(query, "code_challenge", codeChallenge);
        Append(query, "code_challenge_method", "S256");

        var separator = authorizationEndpoint.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        return authorizationEndpoint + separator + query;
    }

    private static void Append(StringBuilder query, string key, string value)
    {
        if (query.Length > 0)
        {
            query.Append('&');
        }

        query.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
    }
}
