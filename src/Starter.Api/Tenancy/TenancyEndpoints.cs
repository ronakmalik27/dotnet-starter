using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Starter.Api.Identity;
using Starter.Identity;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the tenancy control plane: anonymous self-serve signup
/// (POST /signup) and the tenant-token mint (POST /tenants/{id}/token). Business
/// rules live behind <see cref="ITenancyApi"/> and <see cref="IIdentityApi"/>;
/// this layer only shapes requests, transports, and the problem envelope.
/// Signup reuses the same refresh cookie and token-response the login endpoint
/// uses, so web transport matches login.
/// </summary>
public static class TenancyEndpoints
{
    /// <summary>
    /// The fixed-window rate-limit policy that guards anonymous signup against
    /// tenant/account-creation abuse. Applied to the signup endpoint only; the
    /// composition root defines the policy (partitioned by client IP).
    /// </summary>
    public const string SignupRateLimitPolicy = "signup";

    private const int DeviceLabelMaxLength = 200;

    public static IEndpointRouteBuilder MapTenancyEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Anonymous and rate-limited: a brand-new user + tenant + owner
        // membership are created atomically on the bypass path. Naturally
        // retry-safe (a duplicate email or slug converges on the same outcome),
        // so it rides outside the idempotency filter like the auth endpoints.
        app.MapPost("/api/v1/signup", SignupAsync)
            .AllowAnonymous()
            .RequireRateLimiting(SignupRateLimitPolicy);

        // The tenant-switch mint: an authenticated member trades their session
        // for an access token bound to the tenant. A non-member gets 404, never
        // confirming the tenant exists.
        app.MapPost("/api/v1/tenants/{id:guid}/token", IssueTenantTokenAsync)
            .RequireAuthorization();

        // Accepting an invitation is its OWN endpoint, not a tenant-admin one:
        // the invitee holds no tid or role for the target tenant yet, so it
        // cannot sit behind RequireTenant / RequireTenantRole. It is authorized
        // by possession of the hashed, single-use, expiring token PLUS an
        // authenticated user whose email matches the invitation (the acceptor's
        // defense-in-depth check). It runs cross-tenant on the bypass path.
        app.MapPost("/api/v1/invitations/accept", AcceptInvitationAsync)
            .RequireAuthorization();

        return app;
    }

    private static async Task<IResult> SignupAsync(
        SignupRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            errors["email"] = ["Email is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            errors["password"] = ["Password is required."];
        }

        if (string.IsNullOrWhiteSpace(request.TenantName))
        {
            errors["tenantName"] = ["A tenant name is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Slug))
        {
            errors["slug"] = ["A tenant slug is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.ProvisionSelfServeAsync(
            request.Email!,
            request.Password!,
            request.TenantName!,
            request.Slug!,
            DeviceLabel(http),
            ClientIp(http),
            cancellationToken);

        return result.Match(
            signup =>
            {
                if (signup.Tokens is { } tokens)
                {
                    // Fresh path: auto-login. The access token carries tid = the
                    // new tenant; the refresh cookie is set exactly like login.
                    RefreshCookie.Append(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt);
                    return (IResult)TypedResults.Created(
                        (string?)null, new TokenResponse(tokens.AccessToken, tokens.AccessTokenExpiresIn));
                }

                // Enumeration-safe generic success: the email already had an
                // account (nothing created), or auto-login was skipped. Same 201
                // as fresh, with no cookie and empty tokens; the client logs in
                // normally. This never reveals whether the email pre-existed.
                return (IResult)TypedResults.Created((string?)null, new TokenResponse(string.Empty, 0));
            },
            error => error.Code switch
            {
                // A slug is caller-supplied and not a secret, so confirming it is
                // taken is fine.
                "tenancy.slug_taken" => SlugTaken(http, error.Message),
                // Bad email / weak password / bad slug shape -> 422.
                _ => error.ToProblemResult(http),
            });
    }

    private static async Task<IResult> IssueTenantTokenAsync(
        Guid id,
        IIdentityApi identity,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // RequireAuthorization gates the route; read sub + sid off the token.
        // Fail closed if either is somehow absent.
        var userId = http.User.GetUserId();
        var sessionId = http.User.GetSessionId();
        if (userId is null || sessionId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (!await tenancy.IsActiveMemberAsync(id, userId.Value, cancellationToken))
        {
            // 404 not 403: a non-member must not learn the tenant exists (the
            // same cross-tenant 404 posture the isolation boundary takes).
            return MembershipNotFound(http);
        }

        var result = await identity.SelectTenantAsync(userId.Value, sessionId.Value, id, cancellationToken);
        return result.Match(
            token => (IResult)TypedResults.Ok(new TokenResponse(token.AccessToken, token.AccessTokenExpiresIn)),
            // A revoked/expired/version-stale session is a generic 401.
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> AcceptInvitationAsync(
        AcceptInvitationRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // RequireAuthorization gates the route; read sub off the token. Fail
        // closed if it is somehow absent.
        var userId = http.User.GetUserId();
        if (userId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return Validation(http, "token", "An invitation token is required.");
        }

        var result = await tenancy.AcceptInvitationAsync(userId.Value, request.Token, cancellationToken);
        return result.Match(
            accepted => (IResult)TypedResults.Ok(new AcceptInvitationResponse(accepted.TenantId, accepted.Role)),
            error => TenancyProblems.From(http, error));
    }

    private static ProblemHttpResult Validation(HttpContext http, string field, string message) =>
        TypedResults.Problem(StarterProblems.Validation(
            http, new Dictionary<string, string[]> { [field] = [message] }));

    private static ProblemHttpResult SlugTaken(HttpContext http, string detail)
    {
        var problem = StarterProblems.ForStatus(http, StatusCodes.Status409Conflict);
        problem.Type = ProblemTypes.TenantSlugTaken;
        problem.Title = "That tenant slug is already taken.";
        problem.Detail = detail;
        problem.Status = StatusCodes.Status409Conflict;
        return TypedResults.Problem(problem);
    }

    private static ProblemHttpResult MembershipNotFound(HttpContext http)
    {
        var problem = StarterProblems.ForStatus(http, StatusCodes.Status404NotFound);
        problem.Type = ProblemTypes.TenantMembershipNotFound;
        problem.Title = "No such tenant membership.";
        problem.Detail = "You are not a member of this tenant, or it does not exist.";
        return TypedResults.Problem(problem);
    }

    private static string? ClientIp(HttpContext http) =>
        http.Connection.RemoteIpAddress?.ToString();

    private static string? DeviceLabel(HttpContext http)
    {
        var label = http.Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(label))
        {
            return null;
        }

        return label.Length <= DeviceLabelMaxLength ? label : label[..DeviceLabelMaxLength];
    }
}

/// <summary>POST /api/v1/signup body.</summary>
public sealed record SignupRequest(string? Email, string? Password, string? TenantName, string? Slug);

/// <summary>POST /api/v1/invitations/accept body.</summary>
public sealed record AcceptInvitationRequest(string? Token);

/// <summary>POST /api/v1/invitations/accept success: the joined tenant and the granted role.</summary>
public sealed record AcceptInvitationResponse(Guid TenantId, string Role);
