using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The only public surface of the Tenancy module. Owns tenants, memberships,
/// and the control-plane operations over them. Starter.Api composes the HTTP
/// endpoints over these commands (modules never self-host routes). Signatures
/// use primitives and platform contract types only, so the module exports no
/// other public type (ModuleSurfaceTests).
/// </summary>
public interface ITenancyApi
{
    /// <summary>
    /// Self-serve signup: creates a brand-new user, a new tenant, and the
    /// caller's owner membership ATOMICALLY in one transaction on the bypass
    /// data source, then (post-commit, best-effort) sends the verification email
    /// and logs the new owner in bound to the new tenant. Success carries the
    /// auto-login tokens on the fresh path (the access token's tid is the new
    /// tenant); it carries no tokens when the email already had an account - the
    /// enumeration-safe generic success that creates nothing and does not leak
    /// that the address pre-existed. A slug already taken is a Conflict
    /// (tenancy.slug_taken); a bad email or weak password is a Validation
    /// failure. "A failure leaves neither a user nor a tenant" is a tested
    /// invariant - every write shares one transaction.
    /// </summary>
    Task<Result<SelfServeSignup>> ProvisionSelfServeAsync(
        string email,
        string password,
        string tenantName,
        string slug,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken);

    /// <summary>
    /// True when <paramref name="userId"/> is an active member of
    /// <paramref name="tenantId"/>. The tenant-token mint gate: it runs on the
    /// bypass path because the caller holds no tid for the tenant yet, so an
    /// RLS-bound lookup keyed on the current-tenant GUC would see nothing. A
    /// non-member (or an absent tenant) is false, so the endpoint answers 404
    /// and never confirms the tenant exists.
    /// </summary>
    Task<bool> IsActiveMemberAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken);
}
