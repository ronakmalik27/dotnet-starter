using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Starter.Api.Platform;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the tenant-admin control plane (multi-tenancy.md section
/// 8): member management, invitations, settings, ownership transfer, soft-delete,
/// and seats - all over the ACTIVE tenant (the singular /api/v1/tenant, resolved
/// from the tid claim). Every route requires a resolved tenant and an
/// authenticated caller (group-level RequireTenant + RequireAuthorization) and a
/// minimum tenant role (per-route RequireTenantRole: member+, admin+, or
/// owner-only). Business rules live behind <see cref="ITenancyApi"/>; this layer
/// shapes requests, transports, and the problem envelope only.
/// </summary>
public static class TenantAdminEndpoints
{
    public static IEndpointRouteBuilder MapTenantAdminEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route role gate, so an unresolved
        // tenant answers 400 tenant-required before any 403 role check.
        var tenant = app.MapGroup("/api/v1/tenant")
            .RequireTenant()
            .RequireAuthorization();

        // Behavior-preserving migration to fine-grained permissions
        // (multi-tenancy.md section 13): the system-role permission sets
        // reproduce the Part I tenant-role thresholds exactly (members:read and
        // seats:read are Member+; members:manage, invitations:manage, and
        // settings:manage are Admin+), so a member is still refused and an admin
        // still granted - now a custom role granting just one of these lets a
        // member do exactly that one thing. The two owner-only lifecycle
        // operations KEEP RequireTenantRole(Owner): their capabilities are
        // owner-reserved and never grantable through a custom role.
        tenant.MapGet("/members", ListMembersAsync).RequirePermission(Permissions.MembersRead);
        tenant.MapPatch("/members/{userId:guid}", ChangeMemberRoleAsync).RequirePermission(Permissions.MembersManage);
        // Removing a member is destructive, so it is refused under an
        // impersonation token (the conservative default, multi-tenancy.md
        // section 7); BlockUnderImpersonation is outermost among the route filters.
        tenant.MapDelete("/members/{userId:guid}", RemoveMemberAsync)
            .BlockUnderImpersonation()
            .RequirePermission(Permissions.MembersManage);

        tenant.MapPost("/invitations", InviteAsync).RequirePermission(Permissions.InvitationsManage);
        tenant.MapGet("/invitations", ListInvitationsAsync).RequirePermission(Permissions.InvitationsManage);
        tenant.MapDelete("/invitations/{id:guid}", RevokeInvitationAsync).RequirePermission(Permissions.InvitationsManage);

        tenant.MapPatch("/", UpdateSettingsAsync).RequirePermission(Permissions.SettingsManage);
        // Ownership transfer and tenant soft-delete are irreversible, so both are
        // refused under an impersonation token on top of their owner-only gate.
        // Their capabilities are owner-reserved, so they stay on the system-role
        // gate and are never grantable through a custom role.
        tenant.MapPost("/transfer-ownership", TransferOwnershipAsync)
            .BlockUnderImpersonation()
            .RequireTenantRole(TenantRole.Owner);
        tenant.MapPost("/delete", SoftDeleteAsync)
            .BlockUnderImpersonation()
            .RequireTenantRole(TenantRole.Owner);

        tenant.MapGet("/seats", GetSeatsAsync).RequirePermission(Permissions.SeatsRead);

        return app;
    }

    private static async Task<IResult> ListMembersAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var members = await tenancy.ListMembersAsync(cancellationToken);
        var items = members
            .Select(member => new MemberResponse(member.UserId, member.Role, member.Status, member.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> ChangeMemberRoleAsync(
        Guid userId,
        ChangeRoleRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (string.IsNullOrWhiteSpace(request.Role))
        {
            return Validation(http, "role", "A role is required.");
        }

        var result = await tenancy.ChangeMemberRoleAsync(callerId.Value, userId, request.Role, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> RemoveMemberAsync(
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

        var result = await tenancy.RemoveMemberAsync(callerId.Value, userId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> InviteAsync(
        InviteRequest request,
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
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            errors["email"] = ["An email is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Role))
        {
            errors["role"] = ["A role is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await tenancy.InviteMemberAsync(
            callerId.Value,
            request.Email!,
            request.Role!,
            // Scope-aware invite (section 16): both set, or both null for a plain
            // tenant invite. The service validates the pair at invite time.
            request.WorkspaceId,
            request.RoleId,
            cancellationToken);
        return result.Match(
            id => (IResult)TypedResults.Created((string?)null, new InvitationCreatedResponse(id)),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> ListInvitationsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var invitations = await tenancy.ListInvitationsAsync(cancellationToken);
        var items = invitations
            .Select(invitation => new InvitationResponse(
                invitation.Id, invitation.Email, invitation.Role, invitation.ExpiresAt, invitation.CreatedAt))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> RevokeInvitationAsync(
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

        var result = await tenancy.RevokeInvitationAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> UpdateSettingsAsync(
        UpdateSettingsRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.UpdateSettingsAsync(
            callerId.Value, request.Name, request.Slug, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> TransferOwnershipAsync(
        TransferOwnershipRequest request,
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
            return Validation(http, "userId", "A target user id is required.");
        }

        var result = await tenancy.TransferOwnershipAsync(callerId.Value, request.UserId, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> SoftDeleteAsync(
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await tenancy.SoftDeleteTenantAsync(callerId.Value, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => TenancyProblems.From(http, error));
    }

    private static async Task<IResult> GetSeatsAsync(
        ITenancyApi tenancy, CancellationToken cancellationToken)
    {
        var (seatLimit, activeMembers) = await tenancy.GetSeatsAsync(cancellationToken);
        return Results.Ok(new SeatsResponse(seatLimit, activeMembers));
    }

    private static ProblemHttpResult Validation(HttpContext http, string field, string message) =>
        TypedResults.Problem(StarterProblems.Validation(
            http, new Dictionary<string, string[]> { [field] = [message] }));
}

/// <summary>PATCH /api/v1/tenant/members/{userId} body.</summary>
public sealed record ChangeRoleRequest(string? Role);

/// <summary>
/// POST /api/v1/tenant/invitations body. A scope-aware invite (multi-tenancy.md
/// section 16) also names a <paramref name="WorkspaceId"/> + <paramref name="RoleId"/>
/// (both together): the custom role to grant at that workspace when the invite is
/// accepted. Both null is a plain tenant invite.
/// </summary>
public sealed record InviteRequest(string? Email, string? Role, Guid? WorkspaceId, Guid? RoleId);

/// <summary>PATCH /api/v1/tenant body: name and/or slug.</summary>
public sealed record UpdateSettingsRequest(string? Name, string? Slug);

/// <summary>POST /api/v1/tenant/transfer-ownership body.</summary>
public sealed record TransferOwnershipRequest(Guid UserId);

/// <summary>GET /api/v1/tenant/members item.</summary>
public sealed record MemberResponse(Guid UserId, string Role, string Status, DateTimeOffset CreatedAt);

/// <summary>POST /api/v1/tenant/invitations success: the new invitation's id.</summary>
public sealed record InvitationCreatedResponse(Guid Id);

/// <summary>GET /api/v1/tenant/invitations item.</summary>
public sealed record InvitationResponse(
    Guid Id, string Email, string Role, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt);

/// <summary>GET /api/v1/tenant/seats success.</summary>
public sealed record SeatsResponse(int SeatLimit, int ActiveMembers);
