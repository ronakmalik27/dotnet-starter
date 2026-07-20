using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Refresh;

/// <summary>
/// Refresh rotation. Every refresh writes a NEW sessions row in
/// the same family and retires the presented one; presenting a retired or
/// revoked token is reuse and revokes the whole family with a security
/// notice (identity.session.revoked). The user's
/// token version is enforced here and only here: a ver bump
/// kills every refresh immediately while access tokens age out within
/// 15 minutes. Every failure is the same generic 401.
/// </summary>
internal sealed class RefreshHandler(
    IdentityDbContext db,
    AccessTokenIssuer accessTokens,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error InvalidRefresh = new(
        ErrorKind.Unauthorized,
        "auth.refresh_invalid",
        "The refresh token is not valid.");

    public async Task<Result<IssuedTokens>> HandleAsync(
        string refreshToken,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        if (refreshToken.Length == 0)
        {
            return InvalidRefresh;
        }

        var now = clock.UtcNow;
        var presentedHash = RefreshTokens.Hash(refreshToken);

        // No transaction for the lookup: a garbage or unknown token - the
        // overwhelming majority of malicious/invalid refresh traffic -
        // should not pay for a BEGIN/ROLLBACK round trip it never needs.
        // The transaction opens below, only
        // once a real session row is found, right before the branches that
        // actually write (reuse revocation, ver-bump revocation, rotation).
        var session = await db.Sessions.SingleOrDefaultAsync(
            candidate => candidate.RefreshHash == presentedHash, cancellationToken);
        if (session is null)
        {
            return InvalidRefresh;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        if (session.RevokedAt is not null)
        {
            // Reuse: this token was already rotated or revoked. Whoever
            // holds it now, the family is compromised.
            await RevokeFamilyForReuseAsync(session, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return InvalidRefresh;
        }

        if (session.ExpiresAt <= now)
        {
            return InvalidRefresh;
        }

        var user = await db.Users.SingleAsync(
            candidate => candidate.Id == session.UserId, cancellationToken);
        if (user.TokenVersion != session.TokenVersion || user.Status != UserStatus.Active)
        {
            // The ver enforcement point. Quietly retire the
            // family: the version bump came from a user-visible action
            // (password change, sign-out-everywhere) that carries its own
            // notification; a second notice here would be noise.
            await RevokeFamilyAsync(session.FamilyId, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return InvalidRefresh;
        }

        // Retire-if-still-active, atomically: two racing refreshes with
        // the same token cannot both rotate. The loser sees zero rows and
        // lands on the reuse path.
        var retired = await db.Sessions
            .Where(candidate => candidate.Id == session.Id && candidate.RevokedAt == null)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(s => s.RevokedAt, now)
                    .SetProperty(s => s.LastActiveAt, now),
                cancellationToken);
        if (retired == 0)
        {
            await RevokeFamilyForReuseAsync(session, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return InvalidRefresh;
        }

        var newToken = RefreshTokens.NewToken();
        var rotated = new Session
        {
            Id = Ids.NewId(now),
            UserId = session.UserId,
            FamilyId = session.FamilyId,
            RefreshHash = RefreshTokens.Hash(newToken),
            TokenVersion = user.TokenVersion,
            DeviceLabel = session.DeviceLabel,
            Ip = ipAddress ?? session.Ip,
            CreatedAt = now,
            LastActiveAt = now,
            // The family deadline is absolute: rotation never extends it
            // (30 days from login, then re-authenticate).
            ExpiresAt = session.ExpiresAt,
        };
        db.Sessions.Add(rotated);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        var accessToken = accessTokens.Issue(user.Id, rotated.Id, user.TokenVersion, now);
        return new IssuedTokens(
            user.Id,
            rotated.Id,
            accessToken,
            (int)StarterAuth.AccessTokenLifetime.TotalSeconds,
            newToken,
            rotated.ExpiresAt);
    }

    private async Task RevokeFamilyForReuseAsync(
        Session presented,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var revoked = await RevokeFamilyAsync(presented.FamilyId, now, cancellationToken);

        // Notify only when this attempt actually killed live sessions: a
        // second replay against an already-dead family changes nothing and
        // must not spam the user (security notices are for state changes).
        if (revoked > 0)
        {
            await outbox.EnqueueAsync(
                db, IdentityEvents.FamilyRevokedForReuse(presented.Id, now), cancellationToken);
            // EnqueueAsync only stages the event/outbox rows; without this
            // the security notification is silently dropped before the
            // caller's transaction.CommitAsync.
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private Task<int> RevokeFamilyAsync(
        Guid familyId,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        db.Sessions
            .Where(candidate => candidate.FamilyId == familyId && candidate.RevokedAt == null)
            .ExecuteUpdateAsync(
                set => set.SetProperty(s => s.RevokedAt, now),
                cancellationToken);
}
