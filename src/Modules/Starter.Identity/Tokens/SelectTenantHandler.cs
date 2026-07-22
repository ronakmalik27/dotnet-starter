using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Tokens;

/// <summary>
/// The tenant-switch mint: reissues the access token for an existing session,
/// now bound to a tenant. It loads the session by id, proves it belongs to the
/// caller and is still live (not revoked, not expired, token version matching an
/// active user), stamps the tenant onto the session, and mints a NEW access
/// token carrying tid - same session, same refresh family, no new refresh token.
/// Because the session row keeps the tenant, a later refresh preserves it.
/// Every liveness miss is one generic Unauthorized: the caller held a valid
/// access token to reach here, but a version bump or revocation inside the
/// 15-minute window still fails closed.
/// </summary>
internal sealed class SelectTenantHandler(
    IdentityDbContext db,
    AccessTokenIssuer accessTokens,
    Clock clock)
{
    private static readonly Error SessionInvalid = new(
        ErrorKind.Unauthorized,
        "auth.session_invalid",
        "The session is not valid for this caller.");

    public async Task<Result<TenantAccessToken>> HandleAsync(
        Guid userId,
        Guid sessionId,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        var session = await db.Sessions.SingleOrDefaultAsync(
            candidate => candidate.Id == sessionId, cancellationToken);
        if (session is null
            || session.UserId != userId
            || session.RevokedAt is not null
            || session.ExpiresAt <= now)
        {
            return SessionInvalid;
        }

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == userId, cancellationToken);
        if (user is null || user.Status != UserStatus.Active || user.TokenVersion != session.TokenVersion)
        {
            return SessionInvalid;
        }

        session.TenantId = tenantId;
        await db.SaveChangesAsync(cancellationToken);

        var accessToken = accessTokens.Issue(user.Id, session.Id, user.TokenVersion, now, tenantId);
        return new TenantAccessToken(accessToken, (int)StarterAuth.AccessTokenLifetime.TotalSeconds);
    }
}
