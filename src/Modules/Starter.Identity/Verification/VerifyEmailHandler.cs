using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Verification;

/// <summary>
/// The consuming half of the verification-status split: POST /auth/verify-email
/// marks the token used and the account verified. Consumption
/// is a single guarded UPDATE - two racing submissions of the same token
/// cannot both win, the loser sees zero rows and gets the same generic
/// failure as an unknown token. Unknown, used, and expired tokens all
/// return one error: a consumer holding a bad link learns nothing about
/// why it is bad from this endpoint (the render-only GET is the UX's
/// honest-status source).
/// </summary>
internal sealed class VerifyEmailHandler(
    IdentityDbContext db,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error InvalidToken = new(
        ErrorKind.Validation,
        "auth.verification_token_invalid",
        "This verification link is invalid, already used, or expired.");

    public async Task<Result> HandleAsync(string token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.Length == 0)
        {
            return Result.Failure(InvalidToken);
        }

        var now = clock.UtcNow;
        var tokenHash = OneTimeTokenSecrets.Hash(token);

        // Lookup outside the transaction, same shape as RefreshHandler:
        // garbage tokens - the bulk of hostile traffic - never pay for a
        // BEGIN/ROLLBACK round trip.
        var row = await db.OneTimeTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.TokenHash == tokenHash
                    && candidate.Purpose == OneTimeTokenPurpose.VerifyEmail,
                cancellationToken);
        if (row is null || row.UsedAt is not null || row.ExpiresAt <= now)
        {
            return Result.Failure(InvalidToken);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Consume-if-still-live, atomically: the single-use guarantee
        // lives in this WHERE clause, not in the read above.
        var consumed = await db.OneTimeTokens
            .Where(candidate => candidate.Id == row.Id
                && candidate.UsedAt == null
                && candidate.ExpiresAt > now)
            .ExecuteUpdateAsync(
                set => set.SetProperty(t => t.UsedAt, now),
                cancellationToken);
        if (consumed == 0)
        {
            return Result.Failure(InvalidToken);
        }

        // Flip the account exactly once: a second token consumed after the
        // first (each is independently single-use) must not move the
        // verified timestamp or duplicate the event.
        var verified = await db.Users
            .Where(candidate => candidate.Id == row.UserId && candidate.EmailVerifiedAt == null)
            .ExecuteUpdateAsync(
                set => set.SetProperty(u => u.EmailVerifiedAt, now),
                cancellationToken);
        if (verified > 0)
        {
            await outbox.EnqueueAsync(db, IdentityEvents.UserVerified(row.UserId, now), cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }
}
