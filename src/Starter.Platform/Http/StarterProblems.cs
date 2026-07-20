using System.Diagnostics;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Starter.SharedKernel;

namespace Starter.Platform.Http;

/// <summary>
/// The one place SharedKernel failures and platform conditions become the
/// problem+json envelope: RFC 9457 body with a stable
/// starter:* type slug, plus traceId and (for validation) the field-to-
/// messages errors map. The ErrorKind-to-status table is the contract the
/// ErrorKind XML docs promise; both change together or not at all.
/// </summary>
public static class StarterProblems
{
    /// <summary>The problem+json errors extension key.</summary>
    public const string ErrorsExtension = "errors";

    /// <summary>The problem+json traceId extension key.</summary>
    public const string TraceIdExtension = "traceId";

    /// <summary>
    /// The problem+json serverTime extension key, present on every 401:
    /// a clock-skewed client that rejects "expired" JWTs reads the server
    /// time from the body and compensates.
    /// </summary>
    public const string ServerTimeExtension = "serverTime";

    // One title per condition, shared by the direct factory and the
    // ErrorKind mapping so the two paths can never drift apart.
    private const string InFlightTitle = "A request with this idempotency key is still executing.";

    private const string NotFoundTitle = "The resource does not exist.";

    private const string RateLimitedTitle = "Too many requests.";

    /// <summary>Maps an expected failure to its problem envelope.</summary>
    public static ProblemDetails From(Error error, HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(httpContext);

        var (status, type, title) = Map(error);
        return Create(httpContext, status, type, title, error.Message);
    }

    /// <summary>422 with the field-to-messages errors map.</summary>
    public static ProblemDetails Validation(
        HttpContext httpContext,
        IReadOnlyDictionary<string, string[]> errors)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(errors);

        var problem = Create(
            httpContext,
            StatusCodes.Status422UnprocessableEntity,
            ProblemTypes.Validation,
            "The request failed validation.",
            detail: null);
        problem.Extensions[ErrorsExtension] = errors;
        return problem;
    }

    /// <summary>409 for a same-key request whose first attempt is still executing.</summary>
    public static ProblemDetails IdempotencyInFlight(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return Create(
            httpContext,
            StatusCodes.Status409Conflict,
            ProblemTypes.IdempotencyInFlight,
            InFlightTitle,
            "Retry after the first request finishes; the Retry-After header carries the wait.");
    }

    /// <summary>401 for a request with no authenticated caller.</summary>
    public static ProblemDetails Unauthorized(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return Create(
            httpContext,
            StatusCodes.Status401Unauthorized,
            ProblemTypes.Unauthorized,
            "Authentication is required.",
            detail: null);
    }

    /// <summary>
    /// 403 for an authenticated caller whose email is not verified hitting
    /// a `vrf`-gated endpoint. The detail
    /// is the disabled-with-reason line.
    /// </summary>
    public static ProblemDetails VerificationRequired(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return Create(
            httpContext,
            StatusCodes.Status403Forbidden,
            ProblemTypes.VerificationRequired,
            "Email verification is required.",
            "Verify your email address to use this action.");
    }

    /// <summary>
    /// 500 for a bug. The body carries only the slug and traceId; the
    /// exception itself stays in the server logs (no raw exception ever
    /// reaches a client).
    /// </summary>
    public static ProblemDetails Internal(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return Create(
            httpContext,
            StatusCodes.Status500InternalServerError,
            ProblemTypes.Internal,
            "Something went wrong on our side.",
            detail: null);
    }

    /// <summary>
    /// A client fault raised while reading the request (malformed JSON
    /// body, oversized payload, ..): the framework's status is preserved
    /// (400/413/431), the fixed text never echoes payload or framework
    /// internals.
    /// </summary>
    public static ProblemDetails BadRequest(HttpContext httpContext, int statusCode)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return Create(
            httpContext,
            statusCode,
            ProblemTypes.BadRequest,
            "The request could not be read.",
            "The request body, headers, or size did not match what this endpoint accepts.");
    }

    /// <summary>
    /// The problem envelope for a framework-generated bare status (route
    /// 404/405, content negotiation 415, auth 401, binding 400): every
    /// error response wears the envelope, not only app-thrown ones.
    /// Statuses are preserved verbatim; unlisted 4xx
    /// fall back to the bad-request slug, 5xx to the internal slug.
    /// </summary>
    public static ProblemDetails ForStatus(HttpContext httpContext, int statusCode)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return statusCode switch
        {
            StatusCodes.Status401Unauthorized => Unauthorized(httpContext),
            StatusCodes.Status404NotFound => Create(
                httpContext, statusCode, ProblemTypes.NotFound, NotFoundTitle, detail: null),
            StatusCodes.Status405MethodNotAllowed => Create(
                httpContext, statusCode, ProblemTypes.MethodNotAllowed,
                "The HTTP method is not supported on this resource.", detail: null),
            StatusCodes.Status415UnsupportedMediaType => Create(
                httpContext, statusCode, ProblemTypes.UnsupportedMediaType,
                "The request content type is not supported here.", detail: null),
            StatusCodes.Status429TooManyRequests => Create(
                httpContext, statusCode, ProblemTypes.RateLimited,
                RateLimitedTitle, detail: null),
            >= StatusCodes.Status500InternalServerError => Create(
                httpContext, statusCode, ProblemTypes.Internal,
                "Something went wrong on our side.", detail: null),
            _ => BadRequest(httpContext, statusCode),
        };
    }

    private static (int Status, string Type, string Title) Map(Error error) =>
        error.Kind switch
        {
            ErrorKind.Validation => (
                StatusCodes.Status422UnprocessableEntity,
                ProblemTypes.Validation,
                "The request failed validation."),
            ErrorKind.NotFound => (
                StatusCodes.Status404NotFound,
                ProblemTypes.NotFound,
                NotFoundTitle),
            // ErrorKind.Conflict covers both 409 conditions; the
            // error code's scope prefix picks the slug (ErrorKind XML docs).
            ErrorKind.Conflict when error.Code.StartsWith("idempotency.", StringComparison.Ordinal) => (
                StatusCodes.Status409Conflict,
                ProblemTypes.IdempotencyInFlight,
                InFlightTitle),
            ErrorKind.Conflict => (
                StatusCodes.Status409Conflict,
                ProblemTypes.VersionConflict,
                "The resource changed since it was read."),
            ErrorKind.Unauthorized => (
                StatusCodes.Status401Unauthorized,
                ProblemTypes.Unauthorized,
                "Authentication is required."),
            ErrorKind.RateLimited => (
                StatusCodes.Status429TooManyRequests,
                ProblemTypes.RateLimited,
                RateLimitedTitle),
            _ => throw new ArgumentOutOfRangeException(
                nameof(error),
                error.Kind,
                "ErrorKind has no problem mapping; add the kind and its slug together (ErrorKind XML docs)."),
        };

    private static ProblemDetails Create(
        HttpContext httpContext,
        int status,
        string type,
        string title,
        string? detail)
    {
        var problem = new ProblemDetails
        {
            Status = status,
            Type = type,
            Title = title,
            Detail = detail,
        };
        problem.Extensions[TraceIdExtension] =
            Activity.Current?.Id ?? httpContext.TraceIdentifier;
        if (status == StatusCodes.Status401Unauthorized)
        {
            // Server time in every 401 body so a clock-skewed
            // client can compensate. Resolved lazily because this mapper
            // is static; the Clock singleton is wired by the composition
            // root, and a bare test HttpContext without services simply
            // omits the extension.
            var clock = httpContext.RequestServices?.GetService(typeof(Clock)) as Clock;
            if (clock is not null)
            {
                problem.Extensions[ServerTimeExtension] =
                    clock.UtcNow.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
            }
        }

        return problem;
    }
}
