namespace Starter.SharedKernel;

/// <summary>
/// The expected-failure categories a handler can return (LLD section 1:
/// handlers return Result, exceptions are for bugs). Each kind maps onto the
/// doc 08 problem+json contract in the platform's StarterProblems mapper:
/// Validation to 422 starter:validation, NotFound to 404
/// starter:not-found (including non-membership - never 403, doc 10
/// section 5), Conflict to 409 (starter:version-conflict and
/// starter:idempotency-in-flight), Unauthorized to 401, RateLimited to 429
/// starter:rate-limited. New kinds are added only together with their doc 08
/// problem type.
/// </summary>
public enum ErrorKind
{
    Validation,
    NotFound,
    Conflict,
    Unauthorized,
    RateLimited,
}
