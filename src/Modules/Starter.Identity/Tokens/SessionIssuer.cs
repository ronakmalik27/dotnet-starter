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
    IPolicyDefaults policyDefaults,
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
        Guid? tenantId,
        string? deviceLabel,
        string? ipAddress,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // The refresh-family lifetime is the install-wide platform default
        // (role-templates-and-policy-defaults.md section 3), enforced here at
        // family issue. It is NOT tenant-tightened (only the tid access token is,
        // section 5): the family is not scoped to one tenant. Rotation preserves
        // this absolute deadline, so it is read once, here.
        var defaults = await policyDefaults.GetAsync(cancellationToken);
        var refreshToken = RefreshTokens.NewToken();
        var session = new Session
        {
            Id = Ids.NewId(now),
            UserId = user.Id,
            FamilyId = Ids.NewId(now),
            RefreshHash = RefreshTokens.Hash(refreshToken),
            TokenVersion = user.TokenVersion,
            // Bound to the tenant the caller passed (self-serve signup binds the
            // new tenant); null for a plain login. Refresh preserves it.
            TenantId = tenantId,
            DeviceLabel = deviceLabel,
            Ip = ipAddress,
            CreatedAt = now,
            LastActiveAt = now,
            ExpiresAt = now.AddSeconds(defaults.RefreshLifetimeSeconds),
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

        // The session issue path (login and self-serve signup) never tightens the
        // tid lifetime: a plain login is tenant-less, and a fresh signup's tenant
        // has no override yet. So no tenant override is resolved here; the reported
        // expires_in is exactly the lifetime the minted token carries.
        var accessToken = await accessTokens.IssueAsync(
            user.Id, session.Id, user.TokenVersion, now, tenantId, tenantSessionMaxSeconds: null, cancellationToken);
        return new IssuedTokens(
            user.Id,
            session.Id,
            accessToken.Token,
            accessToken.ExpiresInSeconds,
            refreshToken,
            session.ExpiresAt);
    }
}
