using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Starter.Identity.Domain;
using Starter.SharedKernel;

namespace Starter.Identity.Verification;

/// <summary>
/// POST /auth/verify-email/resend (one-tap resend).
/// Rate-limited 3/h per account against the account's own
/// verify_email issuance history in one_time_tokens - a handler-level
/// guard, because the rate-limiter middleware has not landed; the row
/// count over the indexed (user_id, purpose, created_at) is the same
/// sliding-window check the middleware will express later. An
/// already-verified account resends nothing and still succeeds: a stale
/// banner's tap must not error after verification landed in another tab.
/// </summary>
internal sealed class ResendVerificationHandler(
    IdentityDbContext db,
    VerificationEmailComposer verificationEmail,
    ILogger<ResendVerificationHandler> logger,
    Clock clock)
{
    private static readonly Error ResendLimited = new(
        ErrorKind.RateLimited,
        "auth.verification_resend_limited",
        "Too many verification emails were requested; try again later.");

    public async Task<Result> HandleAsync(Guid userId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == userId, cancellationToken);
        if (user is null || user.Status != UserStatus.Active)
        {
            // An authenticated caller whose row is gone or inert: nothing
            // to verify. NotFound keeps the endpoint honest without
            // inventing a new failure mode.
            return Result.Failure(new Error(
                ErrorKind.NotFound, "auth.user_not_found", "The account does not exist."));
        }

        if (user.EmailVerifiedAt is not null)
        {
            return Result.Success();
        }

        // The sliding window counts ISSUANCES (registration's initial
        // token included), so the guard can never be gamed by alternating
        // endpoints; at the limit, the next resend waits the window out.
        var windowStart = now - EmailVerificationPolicy.IssuanceWindow;
        var issuedInWindow = await db.OneTimeTokens.CountAsync(
            candidate => candidate.UserId == userId
                && candidate.Purpose == OneTimeTokenPurpose.VerifyEmail
                && candidate.CreatedAt > windowStart,
            cancellationToken);
        if (issuedInWindow >= EmailVerificationPolicy.IssuancesPerWindow)
        {
            return Result.Failure(ResendLimited);
        }

        var (row, rawToken) = EmailVerificationPolicy.IssueVerifyEmailToken(userId, now);
        db.OneTimeTokens.Add(row);
        await db.SaveChangesAsync(cancellationToken);

        // Dispatch the fresh token best-effort, the same hook as
        // RegisterHandler: the raw token is still in hand here and the
        // privacy rule keeps it off the domain_events spine. A send failure
        // must not fail the resend - the token is persisted and a later
        // resend re-mints. A production system would move dispatch to a
        // transactional email-outbox for delivery guarantees and uniform
        // timing; this inline post-save send is the starter-appropriate
        // version.
        try
        {
            await verificationEmail.SendVerificationEmailAsync(user.Email, rawToken, cancellationToken);
        }
        catch (Exception exception)
        {
            VerificationEmailLog.DispatchFailed(logger, exception);
        }

        return Result.Success();
    }
}
