namespace Starter.Platform.Auth;

/// <summary>
/// The write sibling of <see cref="IUserDirectory"/>: resolves an email to a global
/// user id, creating the user when absent. Declared in the platform so a consumer
/// (the Tenancy SCIM provisioning flow) never references the Identity module - the
/// exact <see cref="ITenantSsoProvisioner"/> bridge in reverse. Identity implements
/// it (over the identity DbContext, which has no RLS - this is NOT a bypass path),
/// and the composition root registers the same instance for both this port and
/// <see cref="IUserDirectory"/>, so there is one implementation and no drift. Users
/// are global (no tenant), so the create runs on the ordinary request connection.
/// </summary>
public interface IUserProvisioner
{
    /// <summary>
    /// Returns the existing global user id for <paramref name="email"/> (citext,
    /// case-insensitive), or creates a BORN-UNVERIFIED, PASSWORDLESS user and returns
    /// its id. Born-unverified is deliberate (sso-and-scim.md section 5): a SCIM
    /// shell carries no proven address, so the tenant member's first real SSO login
    /// claims it through the existing account-linking table
    /// (<c>ClaimUnverifiedAccount</c>) with no new code path. Idempotent on email -
    /// a concurrent create racing the unique-email index is caught and re-read, so a
    /// repeated provision returns the same id.
    /// </summary>
    Task<Guid> EnsureProvisionedUserAsync(string email, CancellationToken cancellationToken);
}
