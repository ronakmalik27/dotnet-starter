using Starter.Tenancy.Admin;
using Starter.Tenancy.ControlPlane;
using Starter.Tenancy.Rbac;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The module facade: one internal class carrying the public interface,
/// delegating to the control-plane slices (the same vertical-slice shape as the
/// other modules' Api facades). The role resolver and tenant-admin service are
/// request-path RLS reads/writes; the provisioner, membership directory, and
/// invitation acceptor are the explicitly cross-tenant bypass-path slices.
/// </summary>
internal sealed class TenancyApi(
    TenantProvisioner provisioner,
    MembershipDirectory memberships,
    TenantRoleResolver roles,
    PermissionResolver permissions,
    CustomRoleService customRoles,
    WorkspaceService workspaces,
    TeamService teams,
    TenantAdminService admin,
    InvitationAcceptor acceptor,
    PlatformAdminDirectory platformAdmins,
    PlatformAdminService platform) : ITenancyApi
{
    public Task<Result<SelfServeSignup>> ProvisionSelfServeAsync(
        string email,
        string password,
        string tenantName,
        string slug,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken) =>
        provisioner.ProvisionAsync(email, password, tenantName, slug, deviceLabel, ipAddress, cancellationToken);

    public Task<bool> IsActiveMemberAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        memberships.IsActiveMemberAsync(tenantId, userId, cancellationToken);

    public Task<bool> IsTenantActiveAsync(Guid tenantId, CancellationToken cancellationToken) =>
        memberships.IsTenantActiveAsync(tenantId, cancellationToken);

    public Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken cancellationToken) =>
        platformAdmins.IsPlatformAdminAsync(userId, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)>>
        ListTenantsAsync(string? query, int limit, CancellationToken cancellationToken) =>
        platform.ListTenantsAsync(query, limit, cancellationToken);

    public Task<(Guid Id, string Slug, string Name, string Status, string? Plan, int SeatLimit, DateTimeOffset CreatedAt)?>
        GetTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        platform.GetTenantAsync(tenantId, cancellationToken);

    public Task<Result> SuspendTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken) =>
        platform.SuspendTenantAsync(actorUserId, tenantId, cancellationToken);

    public Task<Result> ReactivateTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken) =>
        platform.ReactivateTenantAsync(actorUserId, tenantId, cancellationToken);

    public Task<Result> PlatformDeleteTenantAsync(Guid actorUserId, Guid tenantId, CancellationToken cancellationToken) =>
        platform.DeleteTenantAsync(actorUserId, tenantId, cancellationToken);

    public Task<IReadOnlyList<(Guid UserId, Guid? GrantedBy, DateTimeOffset GrantedAt)>>
        ListPlatformAdminsAsync(CancellationToken cancellationToken) =>
        platform.ListPlatformAdminsAsync(cancellationToken);

    public Task<Result> GrantPlatformAdminAsync(
        Guid actorUserId, Guid? targetUserId, string? email, CancellationToken cancellationToken) =>
        platform.GrantPlatformAdminAsync(actorUserId, targetUserId, email, cancellationToken);

    public Task<Result> RevokePlatformAdminAsync(
        Guid actorUserId, Guid targetUserId, CancellationToken cancellationToken) =>
        platform.RevokePlatformAdminAsync(actorUserId, targetUserId, cancellationToken);

    public Task<Result<(Guid GrantId, Guid SubjectUserId, Guid TargetTenantId, DateTimeOffset ExpiresAt)>>
        StartImpersonationAsync(
            Guid actorUserId, Guid tenantId, Guid? targetUserId, string reason, CancellationToken cancellationToken) =>
        platform.StartImpersonationAsync(actorUserId, tenantId, targetUserId, reason, cancellationToken);

    public Task<Result> EndImpersonationAsync(Guid actorUserId, Guid grantId, CancellationToken cancellationToken) =>
        platform.EndImpersonationAsync(actorUserId, grantId, cancellationToken);

    public Task<TenantRole?> GetCallerRoleAsync(Guid userId, CancellationToken cancellationToken) =>
        roles.GetCallerRoleAsync(userId, cancellationToken);

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(Guid userId, CancellationToken cancellationToken) =>
        permissions.GetCallerPermissionsAsync(userId, cancellationToken);

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid userId, Guid workspaceId, CancellationToken cancellationToken) =>
        permissions.GetCallerPermissionsAsync(userId, workspaceId, cancellationToken);

    public Task<bool> WorkspaceExistsAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        workspaces.WorkspaceExistsAsync(workspaceId, cancellationToken);

    public Task<Result<Guid>> CreateWorkspaceAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken) =>
        workspaces.CreateWorkspaceAsync(callerUserId, slug, name, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        ListWorkspacesAsync(CancellationToken cancellationToken) =>
        workspaces.ListWorkspacesAsync(cancellationToken);

    public Task<Result<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        GetWorkspaceAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        workspaces.GetWorkspaceAsync(workspaceId, cancellationToken);

    public Task<Result> RenameWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, string name, CancellationToken cancellationToken) =>
        workspaces.RenameWorkspaceAsync(callerUserId, workspaceId, name, cancellationToken);

    public Task<Result> ArchiveWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken) =>
        workspaces.ArchiveWorkspaceAsync(callerUserId, workspaceId, cancellationToken);

    public Task<Result> UnarchiveWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken) =>
        workspaces.UnarchiveWorkspaceAsync(callerUserId, workspaceId, cancellationToken);

    public Task<IReadOnlyList<(Guid UserId, string Role, string Status, DateTimeOffset CreatedAt)>>
        ListMembersAsync(CancellationToken cancellationToken) =>
        admin.ListMembersAsync(cancellationToken);

    public Task<Result> ChangeMemberRoleAsync(
        Guid callerUserId, Guid targetUserId, string role, CancellationToken cancellationToken) =>
        admin.ChangeMemberRoleAsync(callerUserId, targetUserId, role, cancellationToken);

    public Task<Result> RemoveMemberAsync(
        Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken) =>
        admin.RemoveMemberAsync(callerUserId, targetUserId, cancellationToken);

    public Task<Result<Guid>> InviteMemberAsync(
        Guid callerUserId,
        string email,
        string role,
        Guid? workspaceId,
        Guid? roleId,
        CancellationToken cancellationToken) =>
        admin.InviteMemberAsync(callerUserId, email, role, workspaceId, roleId, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Email, string Role, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt)>>
        ListInvitationsAsync(CancellationToken cancellationToken) =>
        admin.ListInvitationsAsync(cancellationToken);

    public Task<Result> RevokeInvitationAsync(
        Guid callerUserId, Guid invitationId, CancellationToken cancellationToken) =>
        admin.RevokeInvitationAsync(callerUserId, invitationId, cancellationToken);

    public Task<Result> UpdateSettingsAsync(
        Guid callerUserId, string? name, string? slug, CancellationToken cancellationToken) =>
        admin.UpdateSettingsAsync(callerUserId, name, slug, cancellationToken);

    public Task<Result> TransferOwnershipAsync(
        Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken) =>
        admin.TransferOwnershipAsync(callerUserId, targetUserId, cancellationToken);

    public Task<Result> SoftDeleteTenantAsync(Guid callerUserId, CancellationToken cancellationToken) =>
        admin.SoftDeleteTenantAsync(callerUserId, cancellationToken);

    public Task<(int SeatLimit, int ActiveMembers)> GetSeatsAsync(CancellationToken cancellationToken) =>
        admin.GetSeatsAsync(cancellationToken);

    public Task<Result<(Guid TenantId, string Role)>> AcceptInvitationAsync(
        Guid userId, string token, CancellationToken cancellationToken) =>
        acceptor.AcceptAsync(userId, token, cancellationToken);

    public Task<Result<Guid>> CreateRoleAsync(
        Guid callerUserId,
        string key,
        string name,
        string? description,
        string assignableAt,
        Guid? workspaceId,
        IReadOnlyCollection<string> permissions,
        CancellationToken cancellationToken) =>
        customRoles.CreateRoleAsync(
            callerUserId, key, name, description, assignableAt, workspaceId, permissions, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListRolesAsync(CancellationToken cancellationToken) =>
        customRoles.ListRolesAsync(cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListWorkspaceRolesAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        customRoles.ListWorkspaceRolesAsync(workspaceId, cancellationToken);

    public Task<Result<(Guid Id, string Key, string Name, string? Description, string AssignableAt, IReadOnlyList<string> Permissions, DateTimeOffset CreatedAt)>>
        GetRoleAsync(Guid roleId, CancellationToken cancellationToken) =>
        customRoles.GetRoleAsync(roleId, cancellationToken);

    public Task<Result> UpdateRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string? name,
        string? description,
        IReadOnlyCollection<string>? permissions,
        CancellationToken cancellationToken) =>
        customRoles.UpdateRoleAsync(callerUserId, roleId, name, description, permissions, cancellationToken);

    public Task<Result> DeleteRoleAsync(Guid callerUserId, Guid roleId, CancellationToken cancellationToken) =>
        customRoles.DeleteRoleAsync(callerUserId, roleId, cancellationToken);

    public Task<Result<Guid>> AssignRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string principalType,
        Guid principalId,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken) =>
        customRoles.AssignRoleAsync(
            callerUserId, roleId, principalType, principalId, scopeType, scopeId, cancellationToken);

    public Task<Result> RevokeAssignmentAsync(
        Guid callerUserId, Guid assignmentId, CancellationToken cancellationToken) =>
        customRoles.RevokeAssignmentAsync(callerUserId, assignmentId, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, DateTimeOffset CreatedAt)>>
        ListAssignmentsAsync(CancellationToken cancellationToken) =>
        customRoles.ListAssignmentsAsync(cancellationToken);

    public Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, DateTimeOffset CreatedAt)>>
        ListWorkspaceAssignmentsAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        customRoles.ListWorkspaceAssignmentsAsync(workspaceId, cancellationToken);

    public Task<Result<Guid>> CreateTeamAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken) =>
        teams.CreateTeamAsync(callerUserId, slug, name, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        ListTeamsAsync(CancellationToken cancellationToken) =>
        teams.ListTeamsAsync(cancellationToken);

    public Task<Result<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        GetTeamAsync(Guid teamId, CancellationToken cancellationToken) =>
        teams.GetTeamAsync(teamId, cancellationToken);

    public Task<Result> RenameTeamAsync(
        Guid callerUserId, Guid teamId, string name, CancellationToken cancellationToken) =>
        teams.RenameTeamAsync(callerUserId, teamId, name, cancellationToken);

    public Task<Result> DeleteTeamAsync(Guid callerUserId, Guid teamId, CancellationToken cancellationToken) =>
        teams.DeleteTeamAsync(callerUserId, teamId, cancellationToken);

    public Task<Result<Guid>> AddTeamMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken) =>
        teams.AddMemberAsync(callerUserId, teamId, userId, cancellationToken);

    public Task<Result> RemoveTeamMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken) =>
        teams.RemoveMemberAsync(callerUserId, teamId, userId, cancellationToken);

    public Task<Result<IReadOnlyList<(Guid UserId, DateTimeOffset CreatedAt)>>>
        ListTeamMembersAsync(Guid teamId, CancellationToken cancellationToken) =>
        teams.ListMembersAsync(teamId, cancellationToken);
}
