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
/// HTTP composition for the scoped-RBAC control plane (multi-tenancy.md sections
/// 13, 15): custom-role CRUD and role assignments, all over the ACTIVE tenant
/// (the singular /api/v1/tenant, resolved from the tid claim). Every route
/// requires a resolved tenant and an authenticated caller (group-level
/// RequireTenant + RequireAuthorization) and the roles:manage permission
/// (per-route RequirePermission). Business rules live behind
/// <see cref="ITenancyApi"/>; this layer shapes requests, transports, and the
/// problem envelope only. This increment is tenant-scoped: roles are created
/// with workspace_id null and assignments are at tenant scope.
/// </summary>
public static class RoleAdminEndpoints
{
    // The default assignable scope when a create request omits one: the tenant,
    // the only scope this increment can assign at. It is the wire value the
    // ITenancyApi contract validates (tenant | workspace | both).
    private const string DefaultAssignableAt = "tenant";

    public static IEndpointRouteBuilder MapRoleAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var tenant = app.MapGroup("/api/v1/tenant")
            .RequireTenant()
            .RequireAuthorization();

        tenant.MapPost("/roles", CreateRoleAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapGet("/roles", ListRolesAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapGet("/roles/{id:guid}", GetRoleAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapPatch("/roles/{id:guid}", UpdateRoleAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapDelete("/roles/{id:guid}", DeleteRoleAsync).RequirePermission(Permissions.RolesManage);

        tenant.MapPost("/role-assignments", AssignRoleAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapGet("/role-assignments", ListAssignmentsAsync).RequirePermission(Permissions.RolesManage);
        tenant.MapDelete("/role-assignments/{id:guid}", RevokeAssignmentAsync).RequirePermission(Permissions.RolesManage);

        return app;
    }

    private static async Task<IResult> CreateRoleAsync(
        CreateRoleRequest request,
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
        if (string.IsNullOrWhiteSpace(request.Key))
        {
            errors["key"] = ["A role key is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            errors["name"] = ["A role name is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var assignableAt = string.IsNullOrWhiteSpace(request.AssignableAt)
            ? DefaultAssignableAt
            : request.AssignableAt;

        var result = await tenancy.CreateRoleAsync(
            callerId.Value,
            request.Key!,
            request.Name!,
            request.Description,
            assignableAt,
            // Tenant-owned role: workspace_id null. Workspace-local roles are
            // created on the workspace endpoint (WorkspaceAdminEndpoints).
            workspaceId: null,
            request.Permissions ?? [],
            cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new RoleCreatedResponse(id)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListRolesAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var roles = await tenancy.ListRolesAsync(cancellationToken);
        var items = roles
            .Select(role => new RoleSummaryResponse(
                role.Id, role.Key, role.Name, role.Description, role.AssignableAt, role.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> GetRoleAsync(
        Guid id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await tenancy.GetRoleAsync(id, cancellationToken);
        return result.Match(
            role => Results.Ok(new RoleDetailResponse(
                role.Id, role.Key, role.Name, role.Description, role.AssignableAt, role.Permissions, role.CreatedAt)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> UpdateRoleAsync(
        Guid id,
        UpdateRoleRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdateRoleAsync(
            callerId.Value, id, request.Name, request.Description, request.Permissions, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> DeleteRoleAsync(
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

        var result = await tenancy.DeleteRoleAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> AssignRoleAsync(
        AssignRoleRequest request,
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
        if (request.RoleId == Guid.Empty)
        {
            errors["roleId"] = ["A role id is required."];
        }

        if (request.UserId == Guid.Empty)
        {
            errors["userId"] = ["A user id is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.AssignRoleAsync(
            callerId.Value,
            request.RoleId,
            request.UserId,
            // The tenant control plane grants at tenant scope; scope_id is null.
            AssignmentScopes.Tenant,
            scopeId: null,
            cancellationToken);
        return result.Match(
            assignmentId => (IResult)TypedResults.Created((string?)null, new AssignmentCreatedResponse(assignmentId)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListAssignmentsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var assignments = await tenancy.ListAssignmentsAsync(cancellationToken);
        var items = assignments
            .Select(assignment => new AssignmentResponse(
                assignment.Id,
                assignment.RoleId,
                assignment.PrincipalType,
                assignment.PrincipalId,
                assignment.ScopeType,
                assignment.ScopeId,
                assignment.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> RevokeAssignmentAsync(
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

        var result = await tenancy.RevokeAssignmentAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>POST /api/v1/tenant/roles body.</summary>
public sealed record CreateRoleRequest(
    string? Key, string? Name, string? Description, string? AssignableAt, IReadOnlyList<string>? Permissions);

/// <summary>PATCH /api/v1/tenant/roles/{id} body. A null field leaves that facet unchanged.</summary>
public sealed record UpdateRoleRequest(string? Name, string? Description, IReadOnlyList<string>? Permissions);

/// <summary>POST /api/v1/tenant/role-assignments body: grant a role to a user at tenant scope.</summary>
public sealed record AssignRoleRequest(Guid RoleId, Guid UserId);

/// <summary>POST /api/v1/tenant/roles success: the new role's id.</summary>
public sealed record RoleCreatedResponse(Guid Id);

/// <summary>GET /api/v1/tenant/roles item.</summary>
public sealed record RoleSummaryResponse(
    Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt);

/// <summary>GET /api/v1/tenant/roles/{id} success: the role plus its permission set.</summary>
public sealed record RoleDetailResponse(
    Guid Id,
    string Key,
    string Name,
    string? Description,
    string AssignableAt,
    IReadOnlyList<string> Permissions,
    DateTimeOffset CreatedAt);

/// <summary>POST /api/v1/tenant/role-assignments success: the new assignment's id.</summary>
public sealed record AssignmentCreatedResponse(Guid Id);

/// <summary>GET /api/v1/tenant/role-assignments item.</summary>
public sealed record AssignmentResponse(
    Guid Id,
    Guid RoleId,
    string PrincipalType,
    Guid PrincipalId,
    string ScopeType,
    Guid? ScopeId,
    DateTimeOffset CreatedAt);
