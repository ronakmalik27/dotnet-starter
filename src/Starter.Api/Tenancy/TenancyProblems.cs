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
        "tenancy.workspace_slug_taken" => Conflict(
            http, ProblemTypes.WorkspaceSlugTaken, "That workspace slug is already taken.", error.Message),
        "tenancy.workspace_not_found" => NotFound(
            http, ProblemTypes.WorkspaceNotFound, "The workspace does not exist.", error.Message),
        "tenancy.team_slug_taken" => Conflict(
            http, ProblemTypes.TeamSlugTaken, "That team slug is already taken.", error.Message),
        "tenancy.team_not_found" => NotFound(
            http, ProblemTypes.TeamNotFound, "The team does not exist.", error.Message),
        "tenancy.team_member_exists" => Conflict(
            http, ProblemTypes.TeamMemberExists, "That user is already a team member.", error.Message),
        "tenancy.permission_not_automatable" => Unprocessable(
            http,
            ProblemTypes.PermissionNotAutomatable,
            "This role cannot be assigned to a service account.",
            error.Message),
        // A permission the tenant's plan does not include cannot be added to a
        // custom role (billing-and-entitlements.md section 4a): the commercial
        // gate, so a 402 upgrade answer, not a 403/422 - the same slug the feature
        // gate uses.
        "tenancy.permission_not_in_plan" => Build(
            http,
            StatusCodes.Status402PaymentRequired,
            ProblemTypes.PaymentRequired,
            "Your plan does not include this permission.",
            error.Message),
        // A resource-count quota at its ceiling (quotas.md section 6): the honest
        // answer is 402 upgrade-or-delete, NOT 429 - waiting frees no slot (a gauge,
        // not a window). A DISTINCT slug from the metered starter:quota-exceeded
        // (429), keeping the one-type-one-status contract. Mirrors the
        // permission_not_in_plan 402 case above.
        "tenancy.workspace_quota_reached" => Build(
            http,
            StatusCodes.Status402PaymentRequired,
            ProblemTypes.ResourceQuotaReached,
            "You have reached your plan's workspace limit.",
            error.Message),
        // A domain already claimed by ANY tenant (the global unique index): a
        // definite, non-secret refusal.
        "tenancy.sso_domain_claimed" => Conflict(
            http, ProblemTypes.SsoDomainClaimed, "That domain is already claimed.", error.Message),
        // A non-https SSO issuer refused at save (a security check, not a shape bug).
        "tenancy.sso_issuer_insecure" => Unprocessable(
            http, ProblemTypes.SsoIssuerInsecure, "The SSO issuer must be an https URL.", error.Message),
        _ => error.ToProblemResult(http),
    };

    private static ProblemHttpResult Conflict(HttpContext http, string type, string title, string detail) =>
        Build(http, StatusCodes.Status409Conflict, type, title, detail);

    private static ProblemHttpResult NotFound(HttpContext http, string type, string title, string detail) =>
        Build(http, StatusCodes.Status404NotFound, type, title, detail);

    private static ProblemHttpResult Unprocessable(HttpContext http, string type, string title, string detail) =>
        Build(http, StatusCodes.Status422UnprocessableEntity, type, title, detail);

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
