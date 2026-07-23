using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Identity;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Identity;

/// <summary>
/// HTTP composition for the enterprise-SSO OIDC flow (sso-and-scim.md section 4):
/// the SP-initiated <c>GET /auth/sso/start</c> (resolve tenant, redirect to the
/// tenant's IdP with state/nonce/PKCE, set the CSRF state cookie) and
/// <c>GET /auth/sso/callback</c> (validate and mint a tenant-bound session). Both
/// are anonymous - start MAY carry a bearer (the signed-in "link SSO into my
/// account" confirmation, read like the Google flow does). Business rules live
/// behind <see cref="IIdentityApi"/>; this layer owns the redirect, the cookie, and
/// the problem envelope.
/// </summary>
public static class SsoEndpoints
{
    public static IEndpointRouteBuilder MapSsoEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var sso = app.MapGroup("/api/v1/auth/sso").AllowAnonymous();
        sso.MapGet("/start", StartAsync);
        sso.MapGet("/callback", CallbackAsync);
        return app;
    }

    private static async Task<IResult> StartAsync(
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken,
        string? email = null,
        Guid? tenantId = null)
    {
        if (string.IsNullOrWhiteSpace(email) && tenantId is null)
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["email"] = ["An email or a tenantId is required."] }));
        }

        // The redirect_uri is this host's own callback, computed from the request so
        // it matches between the authorize request and the token exchange.
        var redirectUri = $"{http.Request.Scheme}://{http.Request.Host}{SsoStateCookie.CallbackPath}";

        // The JWT middleware ran even on this anonymous route, so a valid bearer
        // yields the caller's id - the signed-in confirmation for linking SSO into a
        // verified account. Absent for the unauthenticated email-routing entry.
        var result = await identity.StartSsoAsync(
            email, tenantId, http.User.GetUserId(), redirectUri, cancellationToken);
        return result.Match(
            start =>
            {
                SsoStateCookie.Append(http.Response, start.State);
                // 302 to the tenant's IdP authorize endpoint. The state cookie rides
                // SameSite=Lax so it survives the top-level GET redirect back.
                return Results.Redirect(start.AuthorizeUrl);
            },
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> CallbackAsync(
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken,
        string? state = null,
        string? code = null)
    {
        http.Request.Cookies.TryGetValue(SsoStateCookie.Name, out var stateCookie);

        var result = await identity.CompleteSsoAsync(
            state ?? string.Empty,
            code ?? string.Empty,
            stateCookie,
            http.Request.Headers.UserAgent.ToString(),
            http.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
        return result.Match(
            tokens =>
            {
                // The single-use state is consumed; clear its cookie either way.
                SsoStateCookie.Delete(http.Response);
                RefreshCookie.Append(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt);
                return (IResult)Results.Ok(new TokenResponse(tokens.AccessToken, tokens.AccessTokenExpiresIn));
            },
            error =>
            {
                SsoStateCookie.Delete(http.Response);
                return error.Code switch
                {
                    // The SSO email already belongs to a VERIFIED account and the
                    // unauthenticated redirect flow carried no signed-in confirmation:
                    // the no-silent-merge rule, reusing the same slug the Google flow
                    // uses so clients drive the "sign in first, then link" step. This
                    // is also the takeover-refusal outcome when a second tenant's IdP
                    // asserts a victim's email (sso-and-scim.md section 4.3).
                    "auth.sso_link_confirmation_required" => LinkConfirmationRequired(http, error.Message),
                    _ => error.ToProblemResult(http),
                };
            });
    }

    private static ProblemHttpResult LinkConfirmationRequired(HttpContext http, string detail)
    {
        var problem = StarterProblems.ForStatus(http, StatusCodes.Status409Conflict);
        problem.Type = ProblemTypes.LinkConfirmationRequired;
        problem.Title = "This email already belongs to an account.";
        problem.Detail = detail;
        problem.Status = StatusCodes.Status409Conflict;
        return TypedResults.Problem(problem);
    }
}

/// <summary>
/// The SSO CSRF state cookie: HttpOnly + Secure + SameSite=Lax, path-scoped to the
/// SSO endpoints. Lax (not Strict) is deliberate - it survives the top-level GET
/// redirect back from the IdP, which Strict would silently drop, breaking every
/// login (sso-and-scim.md section 4.1).
/// </summary>
internal static class SsoStateCookie
{
    public const string Name = "starter_sso_state";

    public const string CallbackPath = "/api/v1/auth/sso/callback";

    private const string Path = "/api/v1/auth/sso";

    public static void Append(HttpResponse response, string state) =>
        // MaxAge (a relative TimeSpan), not Expires: it bounds the cookie to the
        // login flow without reading the wall clock here (Clock owns time; a raw
        // DateTimeOffset.UtcNow is banned outside the SharedKernel).
        response.Cookies.Append(Name, state, Options(TimeSpan.FromMinutes(10)));

    public static void Delete(HttpResponse response) =>
        response.Cookies.Delete(Name, Options(maxAge: null));

    private static CookieOptions Options(TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = Path,
        MaxAge = maxAge,
    };
}
