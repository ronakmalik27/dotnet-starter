using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Starter.Platform.Http;
using Starter.SharedKernel;

namespace Starter.Api.Platform;

/// <summary>
/// Shapes platform control-plane failures into their stable problem envelopes.
/// Most SharedKernel errors map straight through the generic ErrorKind table
/// (Validation -> 422, NotFound -> 404, Unauthorized -> 401); the two Conflict
/// conditions that the generic table would render as a bare version-conflict -
/// a tenant-lifecycle state clash and the last-platform-admin lockout guard -
/// are special-cased here by their stable error code so the type slug is exact.
/// </summary>
internal static class PlatformAdminProblems
{
    /// <summary>Maps a platform control-plane error to its problem result, by code.</summary>
    public static IResult From(HttpContext http, Error error) => error.Code switch
    {
        "platform.tenant_state" => Conflict(
            http, ProblemTypes.TenantStateConflict, "The tenant is not in a state that allows this.", error.Message),
        "platform.last_admin" => Conflict(
            http, ProblemTypes.PlatformLastAdmin, "The last platform admin cannot be revoked.", error.Message),
        "platform.plan_key_taken" => Conflict(
            http, ProblemTypes.PlatformPlanKeyTaken, "That plan key is already taken.", error.Message),
        "platform.plan_default_conflict" => Conflict(
            http, ProblemTypes.PlatformPlanDefaultConflict, "Another plan is already the default.", error.Message),
        _ => error.ToProblemResult(http),
    };

    private static ProblemHttpResult Conflict(HttpContext http, string type, string title, string detail)
    {
        var problem = StarterProblems.ForStatus(http, StatusCodes.Status409Conflict);
        problem.Type = type;
        problem.Title = title;
        problem.Detail = detail;
        problem.Status = StatusCodes.Status409Conflict;
        return TypedResults.Problem(problem);
    }
}
