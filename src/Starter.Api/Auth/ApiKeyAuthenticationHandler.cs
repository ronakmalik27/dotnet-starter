using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Starter.Tenancy;
using Starter.Platform.Auth;

namespace Starter.Api.Auth;

/// <summary>
/// The API-key authentication scheme (service-accounts.md section 3): reads the
/// presented key, hashes it, and resolves it through <see cref="ITenancyApi"/> -
/// the Api layer cannot touch the bypass source (the arch test forbids it), so
/// resolution lives in the allowlisted Tenancy control-plane resolver reached
/// through the module facade, exactly as the impersonation guard reaches its
/// allowlisted reader. On a hit it builds a principal carrying <c>sub</c> = the
/// service-account id, <c>tid</c> = the resolved tenant, and <c>pt</c> =
/// service_account; the existing <c>TenantResolutionMiddleware</c> then binds the
/// tenant from <c>tid</c> with no new code. On a miss (unknown, revoked, or
/// expired - all one outcome) it fails, which the JWT scheme's forwarded
/// challenge turns into a 401.
/// </summary>
internal sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ITenancyApi tenancy)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!ApiKeyCredential.TryRead(Request, out var rawKey))
        {
            // No API key on this request: not our credential. NoResult (not Fail)
            // so the pipeline is unaffected; the forwarding selector only routes
            // sk_/X-Api-Key requests here, so this is defensive.
            return AuthenticateResult.NoResult();
        }

        var keyHash = ApiKeyCredential.Hash(rawKey);
        var resolved = await tenancy.ResolveApiKeyAsync(keyHash, Context.RequestAborted);
        if (resolved is not { } key)
        {
            // Unknown, revoked, or expired: one generic failure, so a holder
            // cannot probe which keys exist. The forwarded challenge yields 401.
            return AuthenticateResult.Fail("The API key is invalid.");
        }

        var claims = new[]
        {
            new Claim(StarterClaims.Sub, key.ServiceAccountId.ToString()),
            new Claim(StarterClaims.Tid, key.TenantId.ToString()),
            new Claim(StarterClaims.Pt, PrincipalTypes.ServiceAccount),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name, StarterClaims.Sub, roleType: null);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
