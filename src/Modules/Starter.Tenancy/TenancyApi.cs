using Starter.Platform.Auth;
using Starter.Tenancy.ControlPlane;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The module facade: one internal class carrying the public interface,
/// delegating to the control-plane slices (the same vertical-slice shape as the
/// other modules' Api facades).
/// </summary>
internal sealed class TenancyApi(TenantProvisioner provisioner, MembershipDirectory memberships) : ITenancyApi
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
}
