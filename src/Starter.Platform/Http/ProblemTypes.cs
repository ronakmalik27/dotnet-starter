namespace Starter.Platform.Http;

/// <summary>
/// The stable doc 08 section 1 problem type slugs. Slugs never change
/// meaning (doc 13 section 11); new error conditions get new slugs in the
/// same PR as the endpoint that produces them. A slug is a valid RFC 9457
/// type URI (scheme "starter").
/// </summary>
public static class ProblemTypes
{
    /// <summary>422: request shape or field values are wrong (doc 08 section 1).</summary>
    public const string Validation = "starter:validation";

    /// <summary>404: resource absent, including non-membership - never 403 (doc 10 section 5).</summary>
    public const string NotFound = "starter:not-found";

    /// <summary>409: optimistic-concurrency version mismatch (doc 08 section 1).</summary>
    public const string VersionConflict = "starter:version-conflict";

    /// <summary>409: same idempotency key, first request still executing (LLD 7.2).</summary>
    public const string IdempotencyInFlight = "starter:idempotency-in-flight";

    /// <summary>401: missing or invalid authentication.</summary>
    public const string Unauthorized = "starter:unauthorized";

    /// <summary>429: rate limit exceeded (doc 10 4.6 owns the limit table).</summary>
    public const string RateLimited = "starter:rate-limited";

    /// <summary>
    /// 403: the caller is authenticated but the account's email is not
    /// verified, and this endpoint carries the `vrf` capability (doc 08
    /// section 1 shorthand; doc 10 section 5). Deliberately not 404: the
    /// 404-for-non-membership rule hides trip-scoped resources, whereas
    /// verification is the caller's own account state and the doc 03 A5
    /// UX needs the reason to render inline.
    /// </summary>
    public const string VerificationRequired = "starter:verification-required";

    /// <summary>400 family (400/413/431/..): the request could not be read - malformed body, oversized payload (doc 08 section 1).</summary>
    public const string BadRequest = "starter:bad-request";

    /// <summary>405: the HTTP method is not supported on this route (doc 08 section 1).</summary>
    public const string MethodNotAllowed = "starter:method-not-allowed";

    /// <summary>415: the request content type is not accepted by this endpoint (doc 08 section 1).</summary>
    public const string UnsupportedMediaType = "starter:unsupported-media-type";

    /// <summary>
    /// 409: the Google-verified email already belongs to a VERIFIED
    /// account and the request carried no live session for it (doc 10
    /// 4.5: linking into a verified account requires a signed-in
    /// confirmation; silent merge never happens). The client signs the
    /// user in to the existing account and retries the Google exchange
    /// with that access token attached.
    /// </summary>
    public const string LinkConfirmationRequired = "starter:link-confirmation-required";

    /// <summary>500: an unexpected server fault; details stay in the logs.</summary>
    public const string Internal = "starter:internal";

    /// <summary>
    /// 501: the request names a documented capability whose implementation
    /// has not landed yet (e.g. the register/login inviteToken before the
    /// Trips join flow ships - doc 08 section 2.1 note). Failing loudly
    /// beats silently ignoring the field.
    /// </summary>
    public const string NotImplemented = "starter:not-implemented";
}
