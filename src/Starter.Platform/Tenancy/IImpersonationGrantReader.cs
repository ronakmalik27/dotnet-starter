namespace Starter.Platform.Tenancy;

/// <summary>
/// The narrow seam the per-request impersonation guard needs to re-check a
/// grant, declared in the platform so the guard middleware never references the
/// Tenancy module (the same port pattern <see cref="IImpersonationGrantReader"/>
/// shares with the role-reader and user-directory seams). The Tenancy module
/// implements it as a bypass-path read of platform.impersonation_grants, and the
/// composition root bridges this port to that implementation.
/// <para>
/// It is deliberately the bypass path: the grant table carries no RLS and is
/// keyed by grant id, so the guard can re-check any session with a single
/// indexed read on the primary key. This is why the implementation is on the
/// bypass-containment allowlist.
/// </para>
/// </summary>
public interface IImpersonationGrantReader
{
    /// <summary>
    /// True only when the grant exists, has not been ended (ended_at IS NULL),
    /// and has not passed its expiry (now &lt; expires_at). A missing, ended, or
    /// expired grant is false, so the guard rejects the request immediately -
    /// ending a session takes effect on the next request, not at token expiry.
    /// The expiry comparison uses the database clock so it is monotonic with the
    /// grant's own issued_at / expires_at stamps.
    /// </summary>
    Task<bool> IsGrantActiveAsync(Guid grantId, CancellationToken cancellationToken);
}
