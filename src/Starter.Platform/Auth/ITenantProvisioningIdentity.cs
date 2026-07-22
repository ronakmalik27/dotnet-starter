using System.Data.Common;
using Microsoft.EntityFrameworkCore.Storage;
using Starter.SharedKernel;

namespace Starter.Platform.Auth;

/// <summary>
/// The narrow Identity seam the tenancy self-serve provisioner depends on,
/// declared in the platform so the Tenancy module never references the Identity
/// module (modules never reference one another - the composition root bridges
/// this port to the Identity implementation). The Identity module's public
/// interface inherits this, and the composition root registers the same
/// instance for both, so there is one implementation and no drift.
/// <para>
/// It carries exactly the three Identity operations provisioning needs: stage a
/// registration on the provisioner's shared transaction, send the verification
/// email post-commit, and issue an auto-login session for the new owner bound to
/// the new tenant.
/// </para>
/// </summary>
public interface ITenantProvisioningIdentity
{
    /// <summary>
    /// Stages a new account on the caller-owned <paramref name="sharedConnection"/>
    /// and <paramref name="sharedTransaction"/> without committing (the caller
    /// commits the user, the tenant, and the membership together). Returns the
    /// staged account's id and raw verification token, or an email-already-exists
    /// report that staged nothing (the enumeration-safe contract). Failures are
    /// Validation only (email shape, password policy).
    /// </summary>
    Task<Result<StagedRegistration>> StageRegistrationAsync(
        DbConnection sharedConnection,
        IDbContextTransaction sharedTransaction,
        string email,
        string password,
        CancellationToken cancellationToken);

    /// <summary>
    /// Sends the verify-email message for an address with the raw token already
    /// in hand (the provisioner holds it post-commit). Best-effort by contract.
    /// </summary>
    Task SendVerificationEmailAsync(string email, string rawToken, CancellationToken cancellationToken);

    /// <summary>
    /// Issues a session for an established user id, optionally tenant-bound (the
    /// access token then carries tid), and returns the tokens. An absent or
    /// inactive user is a generic Unauthorized.
    /// </summary>
    Task<Result<IssuedTokens>> IssueSessionForAsync(
        Guid userId,
        Guid? tenantId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);
}
