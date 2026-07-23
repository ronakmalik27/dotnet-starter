using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the tenant-admin enterprise-SSO control plane
/// (sso-and-scim.md sections 2, 3): set the per-tenant OIDC config and claim
/// routing domains, all over the ACTIVE tenant (/api/v1/tenant/sso) and gated by
/// RequirePermission(settings:manage) - the enterprise-SSO setup is an admin act,
/// no new permission atom. The client secret is write-only (accepted, encrypted,
/// never read back). Business rules live behind <see cref="ITenancyApi"/>; this
/// layer shapes requests, transports, and the problem envelope only.
/// </summary>
public static class SsoAdminEndpoints
{
    public static IEndpointRouteBuilder MapSsoAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var sso = app.MapGroup("/api/v1/tenant/sso")
            .RequireTenant()
            .RequireAuthorization();

        sso.MapPut("/config", SetConfigAsync).RequirePermission(Permissions.SettingsManage);
        sso.MapPost("/domains", ClaimDomainAsync).RequirePermission(Permissions.SettingsManage);

        return app;
    }

    private static async Task<IResult> SetConfigAsync(
        SetSsoConfigRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Issuer))
        {
            errors["issuer"] = ["An issuer is required."];
        }

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            errors["clientId"] = ["A client id is required."];
        }

        if (string.IsNullOrWhiteSpace(request.ClientSecret))
        {
            errors["clientSecret"] = ["A client secret is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.SetSsoConfigAsync(
            callerId.Value, request.Issuer!, request.ClientId!, request.ClientSecret!, request.Enabled, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ClaimDomainAsync(
        ClaimSsoDomainRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["domain"] = ["A domain is required."] }));
        }

        var result = await tenancy.ClaimSsoDomainAsync(callerId.Value, request.Domain!, cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new SsoDomainClaimedResponse(id)),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>
/// PUT /api/v1/tenant/sso/config body: the per-tenant OIDC IdP. The issuer MUST be
/// https (refused otherwise). The client secret is write-only - accepted here,
/// stored encrypted, and never returned.
/// </summary>
public sealed record SetSsoConfigRequest(string? Issuer, string? ClientId, string? ClientSecret, bool Enabled);

/// <summary>POST /api/v1/tenant/sso/domains body: an email domain to claim for SSO routing.</summary>
public sealed record ClaimSsoDomainRequest(string? Domain);

/// <summary>POST /api/v1/tenant/sso/domains success: the new claim's id (created unverified; it routes once an operator verifies it).</summary>
public sealed record SsoDomainClaimedResponse(Guid Id);
