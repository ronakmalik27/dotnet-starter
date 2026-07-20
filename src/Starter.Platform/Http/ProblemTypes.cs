namespace Starter.Platform.Http;

/// <summary>
/// The stable problem type slugs. Slugs never change
/// meaning; new error conditions get new slugs in the
/// same change as the endpoint that produces them. A slug is a valid RFC 9457
/// type URI (scheme "starter").
/// </summary>
public static class ProblemTypes
{
    /// <summary>422: request shape or field values are wrong.</summary>
    public const string Validation = "starter:validation";

    /// <summary>404: resource absent, including non-membership - never 403.</summary>
    public const string NotFound = "starter:not-found";

    /// <summary>409: optimistic-concurrency version mismatch.</summary>
    public const string VersionConflict = "starter:version-conflict";

    /// <summary>409: same idempotency key, first request still executing.</summary>
    public const string IdempotencyInFlight = "starter:idempotency-in-flight";

    /// <summary>401: missing or invalid authentication.</summary>
    public const string Unauthorized = "starter:unauthorized";

    /// <summary>
    /// 403: the caller is authenticated but not permitted to act on this
    /// resource - the resource-based owner check (ResourceOperations against
    /// an IOwnedResource) did not grant access. Distinct from the 404-for-
    /// non-membership rule: an existence-sensitive resource returns 404 to
    /// avoid confirming it exists, whereas a non-sensitive owned resource
    /// answers 403 honestly.
    /// </summary>
    public const string Forbidden = "starter:forbidden";

    /// <summary>429: rate limit exceeded.</summary>
    public const string RateLimited = "starter:rate-limited";

    /// <summary>
    /// 403: the caller is authenticated but the account's email is not
    /// verified, and this endpoint carries the `vrf` capability. Deliberately
    /// not 404: the 404-for-non-membership rule hides restricted resources,
    /// whereas verification is the caller's own account state and the
    /// UX needs the reason to render inline.
    /// </summary>
    public const string VerificationRequired = "starter:verification-required";

    /// <summary>400 family (400/413/431/..): the request could not be read - malformed body, oversized payload.</summary>
    public const string BadRequest = "starter:bad-request";

    /// <summary>405: the HTTP method is not supported on this route.</summary>
    public const string MethodNotAllowed = "starter:method-not-allowed";

    /// <summary>415: the request content type is not accepted by this endpoint.</summary>
    public const string UnsupportedMediaType = "starter:unsupported-media-type";

    /// <summary>
    /// 409: the Google-verified email already belongs to a VERIFIED
    /// account and the request carried no live session for it (linking
    /// into a verified account requires a signed-in
    /// confirmation; silent merge never happens). The client signs the
    /// user in to the existing account and retries the Google exchange
    /// with that access token attached.
    /// </summary>
    public const string LinkConfirmationRequired = "starter:link-confirmation-required";

    /// <summary>500: an unexpected server fault; details stay in the logs.</summary>
    public const string Internal = "starter:internal";

    /// <summary>
    /// 501: the request names a documented capability whose implementation
    /// has not landed yet (e.g. an optional field accepted before its
    /// feature ships). Failing loudly
    /// beats silently ignoring the field.
    /// </summary>
    public const string NotImplemented = "starter:not-implemented";
}
