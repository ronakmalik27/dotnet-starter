namespace Starter.Platform.Auth;

/// <summary>
/// The seam the SSO sign-in flow uses to JIT-provision a membership into the
/// tenant whose IdP just authenticated the user (sso-and-scim.md section 4),
/// declared in the platform so the Identity module never references the Tenancy
/// module or writes the <c>tenancy.memberships</c> table directly. The Tenancy
/// module implements it on the bypass data source (the user holds no tid for the
/// tenant yet, so the write is genuinely cross-tenant, exactly like self-serve
/// provisioning and invitation accept); the composition root bridges the port to
/// that implementation.
/// </summary>
public interface ITenantSsoProvisioner
{
    /// <summary>
    /// Ensures <paramref name="userId"/> is an active member of
    /// <paramref name="tenantId"/> with the default member role, creating the
    /// membership just-in-time when absent and emitting
    /// <c>tenancy.membership.created</c> only on a fresh create. Idempotent - an
    /// existing membership is a no-op. The user is provisioned ONLY into the tenant
    /// whose IdP authenticated them; no other tenant's access is affected.
    /// </summary>
    Task EnsureMembershipAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken);
}
