using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Tokens;

/// <summary>
/// The one place a proven identity becomes a session: a fresh
/// refresh-token family row, the session event, and the ES256
/// access JWT. Session issuance is method-agnostic by design (deferred-
/// readiness): password login and Google sign-in both land here, so
/// an OIDC-authenticated user gets exactly the tokens a password login
/// gets - there is no parallel token path to drift.
/// </summary>
internal sealed class SessionIssuer(
    IdentityDbContext db,
    AccessTokenIssuer accessTokens,
    OutboxWriter outbox)
{
    /// <summary>
    /// Writes the session row and its event, atomically TOGETHER with
    /// everything the calling handler already staged on the context (a
    /// login rehash, a Google account claim): the caller's writes and the
    /// session must land in one transaction, or a crash between them
    /// issues tokens for state that never persisted. Joins the caller's
    /// open transaction when there is one (the Google linking paths);
    /// otherwise opens and commits its own (login). The outbox write
    /// requires the transaction to be open BEFORE enqueueing (the
    /// write rule; OutboxWriter enforces it).
    /// </summary>
    public async Task<IssuedTokens> IssueAsync(
        User user,
        string? deviceLabel,
        string? ipAddress,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var refreshToken = RefreshTokens.NewToken();
        var session = new Session
        {
            Id = Ids.NewId(now),
            UserId = user.Id,
            FamilyId = Ids.NewId(now),
            RefreshHash = RefreshTokens.Hash(refreshToken),
            TokenVersion = user.TokenVersion,
            DeviceLabel = deviceLabel,
            Ip = ipAddress,
            CreatedAt = now,
            LastActiveAt = now,
            ExpiresAt = now.Add(StarterAuth.RefreshFamilyLifetime),
        };

        var ownsTransaction = db.Database.CurrentTransaction is null;
        var transaction = db.Database.CurrentTransaction
            ?? await db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            db.Sessions.Add(session);
            // The IP is persisted on the session row above (session.Ip), not
            // on the domain_events spine: the event payload carries the coarse
            // device label only (privacy rule - the append-only spine keeps no
            // per-row-erasable PII).
            await outbox.EnqueueAsync(
                db,
                IdentityEvents.SessionCreated(session.Id, user.Id, deviceLabel, now),
                cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            if (ownsTransaction)
            {
                await transaction.CommitAsync(cancellationToken);
            }
        }
        finally
        {
            if (ownsTransaction)
            {
                await transaction.DisposeAsync();
            }
        }

        var accessToken = accessTokens.Issue(user.Id, session.Id, user.TokenVersion, now);
        return new IssuedTokens(
            user.Id,
            session.Id,
            accessToken,
            (int)StarterAuth.AccessTokenLifetime.TotalSeconds,
            refreshToken,
            session.ExpiresAt);
    }
}
