using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Starter.Platform.Http;
using Starter.SharedKernel;

namespace Starter.Api.Tenancy;

/// <summary>
/// Shapes Tenancy control-plane failures into their stable problem envelopes.
/// Most SharedKernel errors map straight through the generic ErrorKind table
/// (Validation -> 422, NotFound -> 404); the ones that need a dedicated slug -
/// the tenancy conflicts and the invitation-invalid outcome, which the generic
/// table would render as a bare version-conflict or not-found - are special-cased
/// here by their stable error code so the type slug is exact and honest.
/// </summary>
internal static class TenancyProblems
{
    /// <summary>Maps a Tenancy control-plane error to its problem result, by code.</summary>
    public static IResult From(HttpContext http, Error error) => error.Code switch
    {
        "tenancy.slug_taken" => Conflict(
            http, ProblemTypes.TenantSlugTaken, "That tenant slug is already taken.", error.Message),
        "tenancy.last_owner" => Conflict(
            http, ProblemTypes.TenantLastOwner, "The last owner cannot be removed or demoted.", error.Message),
        "tenancy.seat_limit_reached" => Conflict(
            http, ProblemTypes.TenantSeatLimitReached, "The tenant is at its seat limit.", error.Message),
        "tenancy.already_member" => Conflict(
            http, ProblemTypes.TenantMembershipConflict, "That account cannot be added again.", error.Message),
        "tenancy.invitation_invalid" => NotFound(
            http, ProblemTypes.TenantInvitationInvalid, "The invitation is not valid.", error.Message),
        "tenancy.role_key_taken" => Conflict(
            http, ProblemTypes.TenantRoleKeyTaken, "That role key is already taken.", error.Message),
        "tenancy.role_in_use" => Conflict(
            http, ProblemTypes.TenantRoleInUse, "The role is in use and cannot be deleted.", error.Message),
        _ => error.ToProblemResult(http),
    };

    private static ProblemHttpResult Conflict(HttpContext http, string type, string title, string detail) =>
        Build(http, StatusCodes.Status409Conflict, type, title, detail);

    private static ProblemHttpResult NotFound(HttpContext http, string type, string title, string detail) =>
        Build(http, StatusCodes.Status404NotFound, type, title, detail);

    private static ProblemHttpResult Build(HttpContext http, int status, string type, string title, string detail)
    {
        var problem = StarterProblems.ForStatus(http, status);
        problem.Type = type;
        problem.Title = title;
        problem.Detail = detail;
        problem.Status = status;
        return TypedResults.Problem(problem);
    }
}
