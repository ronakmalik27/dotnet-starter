using Starter.Tenancy.Admin;
using Starter.Tenancy.ControlPlane;
using Starter.Tenancy.Rbac;
using Starter.Tenancy.ServiceAccounts;
using Starter.Tenancy.Sso;
using Starter.Platform.Auth;
using Starter.Platform.Dsar;
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
    ServiceAccountService serviceAccounts,
    ApiKeyResolver apiKeys,
    TenantAdminService admin,
    InvitationAcceptor acceptor,
    SsoConfigService sso,
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

    public Task<Result<TenantErasureSnapshot>> EraseTenantAsync(
        Guid actorUserId, Guid tenantId, bool force, CancellationToken cancellationToken) =>
        platform.EraseTenantAsync(actorUserId, tenantId, force, cancellationToken);

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

    public Task<IReadOnlyList<(string Key, string Name, IReadOnlyList<string>? Features, IReadOnlyList<string>? Permissions, IReadOnlyDictionary<string, int> Limits, bool IsDefault, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListPlansAsync(CancellationToken cancellationToken) =>
        platform.ListPlansAsync(cancellationToken);

    public Task<Result> CreatePlanAsync(
        Guid actorUserId,
        string key,
        string name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool isDefault,
        CancellationToken cancellationToken) =>
        platform.CreatePlanAsync(actorUserId, key, name, features, permissions, limits, isDefault, cancellationToken);

    public Task<Result> UpdatePlanAsync(
        Guid actorUserId,
        string key,
        string? name,
        IReadOnlyList<string>? features,
        IReadOnlyList<string>? permissions,
        IReadOnlyDictionary<string, int>? limits,
        bool? isDefault,
        CancellationToken cancellationToken) =>
        platform.UpdatePlanAsync(actorUserId, key, name, features, permissions, limits, isDefault, cancellationToken);

    public Task<Result> AssignPlanAsync(
        Guid actorUserId, Guid tenantId, string planKey, CancellationToken cancellationToken) =>
        platform.AssignPlanAsync(actorUserId, tenantId, planKey, cancellationToken);

    public Task<IReadOnlyList<(string Key, string Description, bool DefaultEnabled, int? RolloutPercentage, bool TenantOverridable, bool Archived, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListFeatureFlagsAsync(CancellationToken cancellationToken) =>
        platform.ListFeatureFlagsAsync(cancellationToken);

    public Task<Result> CreateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string description,
        bool defaultEnabled,
        int? rolloutPercentage,
        bool tenantOverridable,
        CancellationToken cancellationToken) =>
        platform.CreateFeatureFlagAsync(
            actorUserId, key, description, defaultEnabled, rolloutPercentage, tenantOverridable, cancellationToken);

    public Task<Result> UpdateFeatureFlagAsync(
        Guid actorUserId,
        string key,
        string? description,
        bool? defaultEnabled,
        int? rolloutPercentage,
        bool? tenantOverridable,
        bool? archived,
        CancellationToken cancellationToken) =>
        platform.UpdateFeatureFlagAsync(
            actorUserId, key, description, defaultEnabled, rolloutPercentage, tenantOverridable, archived, cancellationToken);

    public Task<IReadOnlyList<(string Key, string Name, string Description, IReadOnlyList<string> Permissions, IReadOnlyList<string> AssignableScopes, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)>>
        ListRoleTemplatesAsync(CancellationToken cancellationToken) =>
        platform.ListRoleTemplatesAsync(cancellationToken);

    public Task<Result> CreateRoleTemplateAsync(
        Guid actorUserId,
        string key,
        string name,
        string description,
        IReadOnlyList<string> permissions,
        IReadOnlyList<string> assignableScopes,
        CancellationToken cancellationToken) =>
        platform.CreateRoleTemplateAsync(
            actorUserId, key, name, description, permissions, assignableScopes, cancellationToken);

    public Task<Result> UpdateRoleTemplateAsync(
        Guid actorUserId,
        string key,
        string? name,
        string? description,
        IReadOnlyList<string>? permissions,
        IReadOnlyList<string>? assignableScopes,
        CancellationToken cancellationToken) =>
        platform.UpdateRoleTemplateAsync(
            actorUserId, key, name, description, permissions, assignableScopes, cancellationToken);

    public Task<Result> DeleteRoleTemplateAsync(Guid actorUserId, string key, CancellationToken cancellationToken) =>
        platform.DeleteRoleTemplateAsync(actorUserId, key, cancellationToken);

    public Task<Result<int>> SeedRoleTemplateAsync(
        Guid actorUserId, string key, Guid? tenantId, CancellationToken cancellationToken) =>
        platform.SeedRoleTemplateAsync(actorUserId, key, tenantId, cancellationToken);

    public Task<(int PasswordMinLength, int AccessTokenLifetimeSeconds, int RefreshLifetimeSeconds, int LockoutMaxAttempts, int LockoutDurationSeconds)>
        GetPolicyDefaultsAsync(CancellationToken cancellationToken) =>
        platform.GetPolicyDefaultsAsync(cancellationToken);

    public Task<Result> UpdatePolicyDefaultsAsync(
        Guid actorUserId,
        int? passwordMinLength,
        int? accessTokenLifetimeSeconds,
        int? refreshLifetimeSeconds,
        int? lockoutMaxAttempts,
        int? lockoutDurationSeconds,
        CancellationToken cancellationToken) =>
        platform.UpdatePolicyDefaultsAsync(
            actorUserId,
            passwordMinLength,
            accessTokenLifetimeSeconds,
            refreshLifetimeSeconds,
            lockoutMaxAttempts,
            lockoutDurationSeconds,
            cancellationToken);

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
        Guid callerUserId, string? name, string? slug, int? sessionMaxSeconds, CancellationToken cancellationToken) =>
        admin.UpdateSettingsAsync(callerUserId, name, slug, sessionMaxSeconds, cancellationToken);

    public Task<Result> TransferOwnershipAsync(
        Guid callerUserId, Guid targetUserId, CancellationToken cancellationToken) =>
        admin.TransferOwnershipAsync(callerUserId, targetUserId, cancellationToken);

    public Task<Result> SoftDeleteTenantAsync(Guid callerUserId, CancellationToken cancellationToken) =>
        admin.SoftDeleteTenantAsync(callerUserId, cancellationToken);

    public Task<Result> RecordDataExportAsync(
        Guid callerUserId, IReadOnlyDictionary<string, int> sectionCounts, CancellationToken cancellationToken) =>
        admin.RecordDataExportAsync(callerUserId, sectionCounts, cancellationToken);

    public Task<(int SeatLimit, int ActiveMembers, string? Plan, IReadOnlyDictionary<string, int> Limits)>
        GetSeatsAsync(CancellationToken cancellationToken) =>
        admin.GetSeatsAsync(cancellationToken);

    public Task<Entitlements> GetCallerEntitlementsAsync(CancellationToken cancellationToken) =>
        admin.GetCallerEntitlementsAsync(cancellationToken);

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

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid principalId, string principalType, CancellationToken cancellationToken) =>
        permissions.GetCallerPermissionsAsync(principalId, principalType, cancellationToken);

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid principalId, Guid workspaceId, string principalType, CancellationToken cancellationToken) =>
        permissions.GetCallerPermissionsAsync(principalId, workspaceId, principalType, cancellationToken);

    public Task<(Guid TenantId, Guid ServiceAccountId)?> ResolveApiKeyAsync(
        string keyHash, CancellationToken cancellationToken) =>
        apiKeys.ResolveApiKeyAsync(keyHash, cancellationToken);

    public Task<Result<(Guid Id, string RawKey, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>>
        CreateServiceAccountAsync(
            Guid callerUserId,
            string name,
            DateTimeOffset? expiresAt,
            Guid? roleId,
            string? scopeType,
            Guid? scopeId,
            CancellationToken cancellationToken) =>
        serviceAccounts.CreateAsync(callerUserId, name, expiresAt, roleId, scopeType, scopeId, cancellationToken);

    public Task<Result<(IReadOnlyList<(Guid Id, string Name, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt)> Items, string? NextCursor)>>
        ListServiceAccountsAsync(int limit, string? cursor, CancellationToken cancellationToken) =>
        serviceAccounts.ListAsync(limit, cursor, cancellationToken);

    public Task<Result<(string RawKey, string KeyPrefix)>>
        RotateServiceAccountAsync(Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken) =>
        serviceAccounts.RotateAsync(callerUserId, serviceAccountId, cancellationToken);

    public Task<Result> RevokeServiceAccountAsync(
        Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken) =>
        serviceAccounts.RevokeAsync(callerUserId, serviceAccountId, cancellationToken);

    public Task<Result> SetSsoConfigAsync(
        Guid callerUserId,
        string issuer,
        string clientId,
        string clientSecret,
        bool enabled,
        CancellationToken cancellationToken) =>
        sso.SetConfigAsync(callerUserId, issuer, clientId, clientSecret, enabled, cancellationToken);

    public Task<Result<Guid>> ClaimSsoDomainAsync(
        Guid callerUserId, string domain, CancellationToken cancellationToken) =>
        sso.ClaimDomainAsync(callerUserId, domain, cancellationToken);
}
