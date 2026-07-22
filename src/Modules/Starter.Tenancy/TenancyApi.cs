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
    TenantAdminService admin,
    InvitationAcceptor acceptor) : ITenancyApi
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

    public Task<TenantRole?> GetCallerRoleAsync(Guid userId, CancellationToken cancellationToken) =>
        roles.GetCallerRoleAsync(userId, cancellationToken);

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
        Guid callerUserId, string email, string role, CancellationToken cancellationToken) =>
        admin.InviteMemberAsync(callerUserId, email, role, cancellationToken);

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
}
