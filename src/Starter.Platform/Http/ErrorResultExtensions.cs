using Microsoft.AspNetCore.Http;
using Starter.SharedKernel;

namespace Starter.Platform.Http;

/// <summary>
/// The endpoint-side bridge from the Result channel to the wire: handlers
/// return Result and their endpoints map failures through
/// here, so every expected failure leaves in the problem envelope.
/// </summary>
public static class ErrorResultExtensions
{
    /// <summary>The error as an RFC 9457 problem+json result.</summary>
    public static IResult ToProblemResult(this Error error, HttpContext httpContext) =>
        TypedResults.Problem(StarterProblems.From(error, httpContext));
}
