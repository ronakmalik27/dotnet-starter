using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Starter.Tenancy;
using Starter.Platform.Auth;

namespace Starter.Api.Auth;

/// <summary>
/// The SCIM bearer authentication scheme (sso-and-scim.md section 5): reads the
/// presented <c>scim_</c> token, hashes it, and resolves it through
/// <see cref="ITenancyApi"/> - the Api layer cannot touch the bypass source (the
/// arch test forbids it), so resolution lives in the allowlisted Tenancy
/// control-plane resolver reached through the module facade, exactly like the
/// API-key scheme. On a hit it builds a NON-resolving principal (CRITICAL rule 3):
/// <c>tid</c> = the resolved tenant (which <see cref="Starter.Platform.Tenancy.TenantResolutionMiddleware"/>
/// then binds), a distinct <c>pt = scim</c> that never resolves through the RBAC
/// resolvers, and a synthetic <c>sub</c> that maps to NO real user. On a miss
/// (unknown, revoked, or expired - all one outcome) it fails, which the JWT scheme's
/// forwarded challenge turns into a 401.
/// <para>
/// The scheme is only ever reached for a request under
/// <c>/scim/v2</c> carrying a <c>scim_</c> bearer (the selector's two conditions),
/// AND the endpoint group additionally pins this scheme with a scheme-specific
/// authorization policy, so a SCIM token can never authenticate a general
/// tenant-admin route even if the selector were misconfigured.
/// </para>
/// </summary>
internal sealed class ScimAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ITenancyApi tenancy)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!ScimCredential.TryRead(Request, out var rawToken))
        {
            // No SCIM token on this request: not our credential. NoResult (not Fail)
            // so the pipeline is unaffected; the selector only routes scim_ requests
            // under /scim/v2 here, so this is defensive.
            return AuthenticateResult.NoResult();
        }

        var tokenHash = ScimCredential.Hash(rawToken);
        var tenantId = await tenancy.ResolveScimTokenAsync(tokenHash, Context.RequestAborted);
        if (tenantId is not Guid resolved)
        {
            // Unknown, revoked, or expired: one generic failure, so a holder cannot
            // probe which tokens exist. The forwarded challenge yields 401.
            return AuthenticateResult.Fail("The SCIM token is invalid.");
        }

        var claims = new[]
        {
            new Claim(StarterClaims.Sub, ScimAuthenticationDefaults.SyntheticSubject),
            new Claim(StarterClaims.Tid, resolved.ToString()),
            new Claim(StarterClaims.Pt, ScimAuthenticationDefaults.PrincipalType),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name, StarterClaims.Sub, roleType: null);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
