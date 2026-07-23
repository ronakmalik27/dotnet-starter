using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Tokens;

/// <summary>
/// Issues a session for an already-established user id, optionally bound to a
/// tenant. Used by self-serve signup auto-login: the provisioner has just
/// committed the new user, tenant, and owner membership, then logs the owner in
/// bound to the new tenant so the returned access token carries its tid. Loads
/// the active user and hands it to the method-agnostic SessionIssuer, exactly
/// the tokens a login gets - but tenant-bound. An absent or inactive user is a
/// generic Unauthorized (the caller treats auto-login as best-effort and the
/// account can still log in normally).
/// </summary>
internal sealed class IssueSessionForHandler(
    IdentityDbContext db,
    SessionIssuer sessions,
    Clock clock)
{
    private static readonly Error UserUnavailable = new(
        ErrorKind.Unauthorized,
        "auth.user_unavailable",
        "No active account is available to issue a session for.");

    public async Task<Result<IssuedTokens>> HandleAsync(
        Guid userId,
        Guid? tenantId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == userId && candidate.Status == UserStatus.Active, cancellationToken);
        if (user is null)
        {
            return UserUnavailable;
        }

        // Self-serve signup auto-login: the fresh tenant has no session-lifetime
        // override yet, so null inherits the platform default.
        return await sessions.IssueAsync(
            user, tenantId, deviceLabel, ipAddress, now, tenantSessionMaxSeconds: null, cancellationToken);
    }
}
