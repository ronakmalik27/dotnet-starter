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
/// HTTP composition for the workspace control plane (multi-tenancy.md sections
/// 12, 13, 15): workspace CRUD plus the workspace-scoped RBAC operations, all
/// over the ACTIVE tenant.
/// <para>
/// Two gate stances. Workspace CRUD is TENANT-level management, so it is gated by
/// the tenant-scope permission (RequirePermission workspaces:read / manage): a
/// tenant admin manages the set of workspaces. The workspace-scoped role and
/// assignment operations are gated at WORKSPACE scope (RequireWorkspace, which
/// 404s a workspace the active tenant cannot see, then the workspace-scoped
/// RequirePermission roles:manage): a workspace admin self-serves roles and
/// grants inside their workspace. RequireWorkspace runs at the group level so the
/// 404-before-403 ordering is automatic. Business rules live behind
/// <see cref="ITenancyApi"/>; this layer shapes requests, transports, and the
/// problem envelope only.
/// </para>
/// </summary>
public static class WorkspaceAdminEndpoints
{
    public static IEndpointRouteBuilder MapWorkspaceAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // The workspace COLLECTION: create and list, gated at tenant scope. No
        // RequireWorkspace here (there is no {workspaceId} to resolve yet).
        var collection = app.MapGroup("/api/v1/workspaces")
            .RequireTenant()
            .RequireAuthorization();

        collection.MapPost("/", CreateWorkspaceAsync).RequirePermission(Permissions.WorkspacesManage);
        collection.MapGet("/", ListWorkspacesAsync).RequirePermission(Permissions.WorkspacesRead);

        // A single workspace and everything scoped to it. The group binds and
        // validates {workspaceId} (RequireWorkspace -> 404 workspace-not-found for
        // an unknown or cross-tenant id), so every route below acts on a real,
        // in-tenant workspace.
        var item = app.MapGroup("/api/v1/workspaces/{workspaceId:guid}")
            .RequireTenant()
            .RequireAuthorization()
            .RequireWorkspace();

        // Managing one workspace's own record stays TENANT-scoped work, and it
        // must keep working while the workspace is archived (rename, archive, and
        // unarchive act on the entity, not on resources inside it), so these do
        // NOT carry RequireActiveWorkspace.
        item.MapGet("/", GetWorkspaceAsync).RequirePermission(Permissions.WorkspacesRead);
        item.MapPatch("/", RenameWorkspaceAsync).RequirePermission(Permissions.WorkspacesManage);
        item.MapPost("/archive", ArchiveWorkspaceAsync).RequirePermission(Permissions.WorkspacesManage);
        item.MapPost("/unarchive", UnarchiveWorkspaceAsync).RequirePermission(Permissions.WorkspacesManage);

        // Workspace-local roles and workspace-scoped grants: gated at WORKSPACE
        // scope, so a tenant admin (roles:manage inherits down) OR a workspace
        // admin (roles:manage granted at this workspace) can self-serve here. The
        // MUTATING routes additionally require an ACTIVE workspace (an archived
        // workspace is read-only, section 20): RequireActiveWorkspace runs after
        // the permission gate, so an authorized caller gets 409 workspace-archived
        // while an unauthorized one still gets 403. The GET reads and the revoke
        // (offboarding cleanup) stay available while archived.
        item.MapPost("/roles", CreateWorkspaceRoleAsync)
            .RequireWorkspacePermission(Permissions.RolesManage)
            .RequireActiveWorkspace();
        item.MapGet("/roles", ListWorkspaceRolesAsync).RequireWorkspacePermission(Permissions.RolesManage);

        item.MapPost("/role-assignments", AssignWorkspaceRoleAsync)
            .RequireWorkspacePermission(Permissions.RolesManage)
            .RequireActiveWorkspace();
        item.MapGet("/role-assignments", ListWorkspaceAssignmentsAsync).RequireWorkspacePermission(Permissions.RolesManage);
        item.MapDelete("/role-assignments/{id:guid}", RevokeWorkspaceAssignmentAsync)
            .RequireWorkspacePermission(Permissions.RolesManage);

        return app;
    }

    // --- Workspace CRUD ---------------------------------------------------

    private static async Task<IResult> CreateWorkspaceAsync(
        CreateWorkspaceRequest request,
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
            errors["slug"] = ["A workspace slug is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            errors["name"] = ["A workspace name is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.CreateWorkspaceAsync(callerId.Value, request.Slug!, request.Name!, cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new WorkspaceCreatedResponse(id)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListWorkspacesAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var workspaces = await tenancy.ListWorkspacesAsync(cancellationToken);
        var items = workspaces
            .Select(workspace => new WorkspaceResponse(
                workspace.Id, workspace.Slug, workspace.Name, workspace.Status, workspace.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> GetWorkspaceAsync(
        Guid workspaceId,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await tenancy.GetWorkspaceAsync(workspaceId, cancellationToken);
        return result.Match(
            workspace => Results.Ok(new WorkspaceResponse(
                workspace.Id, workspace.Slug, workspace.Name, workspace.Status, workspace.CreatedAt)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> RenameWorkspaceAsync(
        Guid workspaceId,
        RenameWorkspaceRequest request,
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
                http, new Dictionary<string, string[]> { ["name"] = ["A workspace name is required."] }));
        }

        var result = await tenancy.RenameWorkspaceAsync(callerId.Value, workspaceId, request.Name!, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ArchiveWorkspaceAsync(
        Guid workspaceId,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.ArchiveWorkspaceAsync(callerId.Value, workspaceId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> UnarchiveWorkspaceAsync(
        Guid workspaceId,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UnarchiveWorkspaceAsync(callerId.Value, workspaceId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    // --- Workspace-local roles and workspace-scoped assignments -----------

    private static async Task<IResult> CreateWorkspaceRoleAsync(
        Guid workspaceId,
        CreateWorkspaceRoleRequest request,
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

        var result = await tenancy.CreateRoleAsync(
            callerId.Value,
            request.Key!,
            request.Name!,
            request.Description,
            // A workspace-local role is assignable at workspace scope only, in
            // this workspace; the service pins workspace_id to the route id.
            AssignmentScopes.Workspace,
            workspaceId,
            request.Permissions ?? [],
            cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new RoleCreatedResponse(id)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListWorkspaceRolesAsync(
        Guid workspaceId, ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var roles = await tenancy.ListWorkspaceRolesAsync(workspaceId, cancellationToken);
        var items = roles
            .Select(role => new RoleSummaryResponse(
                role.Id, role.Key, role.Name, role.Description, role.AssignableAt, role.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> AssignWorkspaceRoleAsync(
        Guid workspaceId,
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
            AssignmentScopes.Workspace,
            workspaceId,
            cancellationToken);
        return result.Match(
            assignmentId => (IResult)TypedResults.Created((string?)null, new AssignmentCreatedResponse(assignmentId)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListWorkspaceAssignmentsAsync(
        Guid workspaceId, ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var assignments = await tenancy.ListWorkspaceAssignmentsAsync(workspaceId, cancellationToken);
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

    private static async Task<IResult> RevokeWorkspaceAssignmentAsync(
        Guid workspaceId,
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

        // Revoke keys on the assignment id (RLS-scoped to the tenant); the
        // workspace segment gated the route. An id in another scope or workspace
        // simply is not found under this tenant's grants.
        var result = await tenancy.RevokeAssignmentAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }
}

/// <summary>POST /api/v1/workspaces body.</summary>
public sealed record CreateWorkspaceRequest(string? Slug, string? Name);

/// <summary>PATCH /api/v1/workspaces/{workspaceId} body.</summary>
public sealed record RenameWorkspaceRequest(string? Name);

/// <summary>POST /api/v1/workspaces success: the new workspace's id.</summary>
public sealed record WorkspaceCreatedResponse(Guid Id);

/// <summary>GET /api/v1/workspaces item / GET /api/v1/workspaces/{id} success.</summary>
public sealed record WorkspaceResponse(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt);

/// <summary>POST /api/v1/workspaces/{workspaceId}/roles body: a workspace-local role (assignable at this workspace).</summary>
public sealed record CreateWorkspaceRoleRequest(
    string? Key, string? Name, string? Description, IReadOnlyList<string>? Permissions);
