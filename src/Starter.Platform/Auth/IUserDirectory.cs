namespace Starter.Platform.Auth;

/// <summary>
/// A minimal read-only view of the global user directory, declared in the
/// platform so a consumer (the Tenancy invitation-accept flow) never references
/// the Identity module. The Identity module's public interface inherits this and
/// the composition root registers the same instance for both, so there is one
/// implementation and no drift - the same port pattern as
/// <see cref="ITenantProvisioningIdentity"/>. Users are global (no tenant, no
/// RLS), so these reads run on the ordinary request connection.
/// </summary>
public interface IUserDirectory
{
    /// <summary>
    /// The active account's email address, or null when no active user has that
    /// id. The invitation-accept flow reads it to require the authenticated
    /// caller's email to match the invitation email (a leaked link must not be
    /// redeemable by a different account).
    /// </summary>
    Task<string?> GetEmailAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// The active account's id for an email address (citext, case-insensitive),
    /// or null when no active user holds it. The invite flow uses it to refuse
    /// inviting an address that is already an active member of the tenant.
    /// </summary>
    Task<Guid?> FindUserIdByEmailAsync(string email, CancellationToken cancellationToken);
}
