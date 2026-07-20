using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Identity;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Identity;

/// <summary>
/// HTTP composition for the Identity module's register / login / refresh,
/// Google sign-in and first-password, and email-verification
/// slices: routes, request shapes, transport concerns (the
/// cookie split and the GET-renders / POST-consumes split), and
/// the problem-details envelope for every failure. Business
/// rules live behind <see cref="IIdentityApi"/>; this layer never touches
/// the module's internals.
/// </summary>
public static class IdentityEndpoints
{
    private const int DeviceLabelMaxLength = 200;

    public static IEndpointRouteBuilder MapIdentityEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var auth = app.MapGroup("/api/v1/auth").AllowAnonymous();

        // Anonymous mutating endpoints ride outside the idempotency
        // filter by construction: the filter keys on the authenticated
        // caller, which these requests do not have. Each is naturally
        // retry-safe instead - registration converges on "same success",
        // login re-issues, refresh reuse is detected and contained.
        auth.MapPost("/register", RegisterAsync);
        auth.MapPost("/login", LoginAsync);
        auth.MapPost("/refresh", RefreshAsync);
        // Anonymous like login, but a caller MAY attach a valid access
        // token: that authenticated identity is the "signed-in
        // confirmation" for linking Google into a verified account.
        auth.MapPost("/google", GoogleAsync);

        // Outside the anonymous group: setting a password requires an
        // authenticated caller (an AllowAnonymous group would override a
        // per-endpoint RequireAuthorization). PUT is idempotent by shape;
        // the idempotency filter is for non-idempotent verbs.
        app.MapPut("/api/v1/auth/password", SetPasswordAsync).RequireAuthorization();

        // The verification-status split: the tokenized GET renders state and
        // is side-effect-free by construction; only the POST consumes.
        // Both are pub - the consumer proves control by holding the token.
        auth.MapGet("/verify-email/{token}", VerificationStatusAsync);
        auth.MapPost("/verify-email", VerifyEmailAsync);

        // Resend is `user`-cap, so it lives OUTSIDE the
        // anonymous group: IAllowAnonymous metadata anywhere on an
        // endpoint would short-circuit RequireAuthorization.
        app.MapPost("/api/v1/auth/verify-email/resend", ResendVerificationAsync)
            .RequireAuthorization();

        return app;
    }

    private static async Task<IResult> RegisterAsync(
        RegisterRequest request,
        IIdentityApi identity,
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

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await identity.RegisterAsync(request.Email!, request.Password!, cancellationToken);
        return result.Match(
            () => Results.Ok(new RegisterResponse(true)),
            error => ToValidationProblem(http, error));
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest request,
        IIdentityApi identity,
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

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await identity.LoginAsync(
            request.Email!,
            request.Password!,
            DeviceLabel(request.DeviceLabel, http),
            ClientIp(http),
            cancellationToken);
        return result.Match(
            tokens =>
            {
                RefreshCookie.Append(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt);
                return (IResult)Results.Ok(new TokenResponse(tokens.AccessToken, tokens.AccessTokenExpiresIn));
            },
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> RefreshAsync(
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // The CSRF companion header: SameSite=Strict already
        // keeps browsers from sending the cookie cross-site; this header is
        // the defense that holds even where SameSite does not, because
        // cross-site forms cannot set custom headers.
        if (http.Request.Headers[RefreshCookie.HeaderName] != RefreshCookie.HeaderValue)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (!http.Request.Cookies.TryGetValue(RefreshCookie.Name, out var refreshToken)
            || string.IsNullOrEmpty(refreshToken))
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await identity.RefreshAsync(refreshToken, ClientIp(http), cancellationToken);
        return result.Match(
            tokens =>
            {
                RefreshCookie.Append(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt);
                return (IResult)Results.Ok(new TokenResponse(tokens.AccessToken, tokens.AccessTokenExpiresIn));
            },
            error =>
            {
                // A rejected refresh is terminal for this cookie (rotation,
                // reuse, expiry, or ver bump): clear it so the SPA falls
                // back to the login screen instead of replaying a dead
                // token - which reads as an attack.
                RefreshCookie.Delete(http.Response);
                return error.ToProblemResult(http);
            });
    }

    private static async Task<IResult> GoogleAsync(
        GoogleSignInRequest request,
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Code))
        {
            errors["code"] = ["The authorization code is required."];
        }

        if (string.IsNullOrWhiteSpace(request.CodeVerifier))
        {
            errors["codeVerifier"] = ["The PKCE code verifier is required."];
        }

        if (string.IsNullOrWhiteSpace(request.RedirectUri))
        {
            errors["redirectUri"] = ["The redirect URI of the authorization request is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Nonce))
        {
            errors["nonce"] = ["The nonce of the authorization request is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await identity.SignInWithGoogleAsync(
            request.Code!,
            request.CodeVerifier!,
            request.RedirectUri!,
            request.Nonce!,
            AuthenticatedUserId(http),
            DeviceLabel(request.DeviceLabel, http),
            ClientIp(http),
            cancellationToken);
        return result.Match(
            tokens =>
            {
                RefreshCookie.Append(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt);
                return (IResult)Results.Ok(new TokenResponse(tokens.AccessToken, tokens.AccessTokenExpiresIn));
            },
            error => error.Code switch
            {
                // A host without Google wiring: the capability is
                // documented but not enabled here.
                "auth.google_not_configured" => NotImplemented(
                    http, "Google sign-in is not configured on this host."),
                // The no-silent-merge rule, as its own slug so
                // clients can drive the "sign in first, then link" step.
                "auth.google_link_confirmation_required" => LinkConfirmationRequired(http, error.Message),
                _ => error.ToProblemResult(http),
            });
    }

    private static async Task<IResult> SetPasswordAsync(
        SetPasswordRequest request,
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(request.CurrentPassword))
        {
            // A current password means change-password, which
            // has not landed; only the first-password case
            // (passwordless Google-created accounts) has shipped.
            return NotImplemented(
                http, "Changing an existing password lands with the change-password flow; this endpoint currently only sets a first password.");
        }

        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["newPassword"] = ["A new password is required."] }));
        }

        var userId = AuthenticatedUserId(http);
        if (userId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await identity.SetPasswordAsync(userId.Value, request.NewPassword!, cancellationToken);
        return result.Match(
            () => (IResult)Results.NoContent(),
            error => error.Code switch
            {
                "auth.password_change_not_implemented" => NotImplemented(
                    http, "This account already has a password; changing it lands with the change-password flow."),
                _ when error.Kind == Starter.SharedKernel.ErrorKind.Validation =>
                    TypedResults.Problem(StarterProblems.Validation(
                        http, new Dictionary<string, string[]> { ["newPassword"] = [error.Message] })),
                _ => error.ToProblemResult(http),
            });
    }

    private static Guid? AuthenticatedUserId(HttpContext http)
    {
        // The JWT middleware ran even on AllowAnonymous routes; a valid
        // bearer token yields the sub claim.
        var sub = http.User.Identity?.IsAuthenticated == true
            ? http.User.FindFirst(StarterClaims.Sub)?.Value
            : null;
        return Guid.TryParse(sub, out var userId) ? userId : null;
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

    private static async Task<IResult> VerifyEmailAsync(
        VerifyEmailRequest request,
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["token"] = ["Token is required."] }));
        }

        var result = await identity.VerifyEmailAsync(request.Token!, cancellationToken);
        return result.Match(
            () => Results.Ok(new VerifyEmailResponse(true)),
            error => TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["token"] = [error.Message] })));
    }

    private static async Task<IResult> VerificationStatusAsync(
        string token,
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await identity.GetVerificationTokenStatusAsync(token, cancellationToken);
        return result.Match(
            status => (IResult)Results.Ok(new VerificationStatusResponse(status switch
            {
                VerificationTokenStatus.Valid => "valid",
                VerificationTokenStatus.Expired => "expired",
                VerificationTokenStatus.Used => "used",
                _ => throw new ArgumentOutOfRangeException(
                    nameof(status), status, "Unmapped VerificationTokenStatus."),
            })),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> ResendVerificationAsync(
        IIdentityApi identity,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // The JWT middleware authenticated the caller; the sub claim is
        // the account. Fail closed if it is somehow absent.
        var subject = http.User.FindFirst(StarterClaims.Sub)?.Value;
        if (!Guid.TryParse(subject, out var userId))
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await identity.ResendVerificationEmailAsync(userId, cancellationToken);
        return result.Match(
            // 202: issuance is accepted; delivery is asynchronous (and
            // joins with the notifications story's email channel).
            () => Results.Accepted(),
            error => error.ToProblemResult(http));
    }

    private static ProblemHttpResult ToValidationProblem(HttpContext http, Starter.SharedKernel.Error error)
    {
        // Module validation failures name exactly one wire field; carry it
        // in the problem-details errors map so clients can highlight the input.
        var field = error.Code.StartsWith("auth.password", StringComparison.Ordinal)
            ? "password"
            : "email";
        return TypedResults.Problem(
            StarterProblems.Validation(http, new Dictionary<string, string[]> { [field] = [error.Message] }));
    }

    private static ProblemHttpResult NotImplemented(HttpContext http, string detail)
    {
        var problem = StarterProblems.ForStatus(http, StatusCodes.Status501NotImplemented);
        problem.Type = ProblemTypes.NotImplemented;
        problem.Title = "This capability has not shipped yet.";
        problem.Detail = detail;
        return TypedResults.Problem(problem);
    }

    private static string? ClientIp(HttpContext http) =>
        http.Connection.RemoteIpAddress?.ToString();

    private static string? DeviceLabel(string? fromRequest, HttpContext http)
    {
        var label = string.IsNullOrWhiteSpace(fromRequest)
            ? http.Request.Headers.UserAgent.ToString()
            : fromRequest.Trim();
        if (string.IsNullOrWhiteSpace(label))
        {
            return null;
        }

        return label.Length <= DeviceLabelMaxLength ? label : label[..DeviceLabelMaxLength];
    }
}

/// <summary>POST /auth/register body.</summary>
public sealed record RegisterRequest(string? Email, string? Password);

/// <summary>POST /auth/login body.</summary>
public sealed record LoginRequest(string? Email, string? Password, string? DeviceLabel);

/// <summary>
/// POST /auth/google body: the client-side authorization
/// request's outputs - code, PKCE verifier, redirect URI, and nonce
/// (code flow + PKCE + nonce, no implicit flow).
/// </summary>
public sealed record GoogleSignInRequest(
    string? Code,
    string? CodeVerifier,
    string? RedirectUri,
    string? Nonce,
    string? DeviceLabel);

/// <summary>PUT /auth/password body (only the first-password case has shipped).</summary>
public sealed record SetPasswordRequest(string? CurrentPassword, string? NewPassword);

/// <summary>POST /auth/register success - identical for new and existing emails.</summary>
public sealed record RegisterResponse(bool Registered);

/// <summary>Login and refresh success body; the refresh token rides the cookie, never JSON.</summary>
public sealed record TokenResponse(string AccessToken, int ExpiresIn);

/// <summary>POST /auth/verify-email body: the consuming POST of the verification-status split.</summary>
public sealed record VerifyEmailRequest(string? Token);

/// <summary>POST /auth/verify-email success.</summary>
public sealed record VerifyEmailResponse(bool Verified);

/// <summary>GET /auth/verify-email/{token} body: render-only token state.</summary>
public sealed record VerificationStatusResponse(string Status);
