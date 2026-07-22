using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the team control plane (multi-tenancy.md sections 14, 20):
/// team CRUD plus team-member management, all over the ACTIVE tenant (the singular
/// /api/v1/tenant, resolved from the tid claim). Every route requires a resolved
/// tenant and an authenticated caller (group-level RequireTenant +
/// RequireAuthorization) and the teams:manage permission (per-route
/// RequirePermission). Business rules live behind <see cref="ITenancyApi"/>; this
/// layer shapes requests, transports, and the problem envelope only. Granting a
/// role TO a team is the assignment API (RoleAdminEndpoints /
/// WorkspaceAdminEndpoints), with principalType = team.
/// </summary>
public static class TeamAdminEndpoints
{
    public static IEndpointRouteBuilder MapTeamAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var teams = app.MapGroup("/api/v1/tenant/teams")
            .RequireTenant()
            .RequireAuthorization();

        teams.MapPost("/", CreateTeamAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapGet("/", ListTeamsAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapGet("/{id:guid}", GetTeamAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapPatch("/{id:guid}", RenameTeamAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapDelete("/{id:guid}", DeleteTeamAsync).RequirePermission(Permissions.TeamsManage);

        teams.MapPost("/{id:guid}/members", AddMemberAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapGet("/{id:guid}/members", ListMembersAsync).RequirePermission(Permissions.TeamsManage);
        teams.MapDelete("/{id:guid}/members/{userId:guid}", RemoveMemberAsync)
            .RequirePermission(Permissions.TeamsManage);

        return app;
    }

    private static async Task<IResult> CreateTeamAsync(
        CreateTeamRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Slug))
        {
            errors["slug"] = ["A team slug is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            errors["name"] = ["A team name is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.CreateTeamAsync(callerId.Value, request.Slug!, request.Name!, cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new TeamCreatedResponse(id)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListTeamsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var teams = await tenancy.ListTeamsAsync(cancellationToken);
        var items = teams
            .Select(team => new TeamResponse(team.Id, team.Slug, team.Name, team.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> GetTeamAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await tenancy.GetTeamAsync(id, cancellationToken);
        return result.Match(
            team => Results.Ok(new TeamResponse(team.Id, team.Slug, team.Name, team.CreatedAt)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> RenameTeamAsync(
        Guid id,
        RenameTeamRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["name"] = ["A team name is required."] }));
        }

        var result = await tenancy.RenameTeamAsync(callerId.Value, id, request.Name!, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> DeleteTeamAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.DeleteTeamAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> AddMemberAsync(
        Guid id,
        AddTeamMemberRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (request.UserId == Guid.Empty)
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http, new Dictionary<string, string[]> { ["userId"] = ["A user id is required."] }));
        }

        var result = await tenancy.AddTeamMemberAsync(callerId.Value, id, request.UserId, cancellationToken);
        return result.Match(
            memberId => (IResult)TypedResults.Created((string?)null, new TeamMemberCreatedResponse(memberId)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListMembersAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await tenancy.ListTeamMembersAsync(id, cancellationToken);
        return result.Match(
            members => Results.Ok(members
                .Select(member => new TeamMemberResponse(member.UserId, member.CreatedAt))
                .ToList()),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> RemoveMemberAsync(
        Guid id,
        Guid userId,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.RemoveTeamMemberAsync(callerId.Value, id, userId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>POST /api/v1/tenant/teams body.</summary>
public sealed record CreateTeamRequest(string? Slug, string? Name);

/// <summary>PATCH /api/v1/tenant/teams/{id} body.</summary>
public sealed record RenameTeamRequest(string? Name);

/// <summary>POST /api/v1/tenant/teams/{id}/members body.</summary>
public sealed record AddTeamMemberRequest(Guid UserId);

/// <summary>POST /api/v1/tenant/teams success: the new team's id.</summary>
public sealed record TeamCreatedResponse(Guid Id);

/// <summary>GET /api/v1/tenant/teams item / GET /api/v1/tenant/teams/{id} success.</summary>
public sealed record TeamResponse(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt);

/// <summary>POST /api/v1/tenant/teams/{id}/members success: the new team-member row id.</summary>
public sealed record TeamMemberCreatedResponse(Guid Id);

/// <summary>GET /api/v1/tenant/teams/{id}/members item.</summary>
public sealed record TeamMemberResponse(Guid UserId, DateTimeOffset CreatedAt);
