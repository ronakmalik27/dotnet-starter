using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Starter.Identity.Domain;
using Starter.SharedKernel;

namespace Starter.Identity.PasswordReset;

/// <summary>
/// Forgot-password: POST /auth/forgot-password { email }. The
/// no-account-enumeration contract shapes the flow, exactly like
/// registration: every outcome returns the same success, whether the
/// address is unknown, malformed, rate-limited, or a real active account.
/// Only a real active account mints a reset_password token and gets a reset
/// email; the raw token is kept in hand for the post-commit dispatch and
/// never rides the outbox (privacy rule). Issuance is rate-limited per
/// account per window, mirroring the verify-email resend guard, so the
/// endpoint cannot be used to flood a mailbox.
/// </summary>
internal sealed class RequestPasswordResetHandler(
    IdentityDbContext db,
    PasswordResetEmailComposer resetEmail,
    ILogger<RequestPasswordResetHandler> logger,
    Clock clock)
{
    public async Task<Result> HandleAsync(string email, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);

        email = email.Trim();

        // A malformed address matches no account: nothing to do, but the
        // answer must look identical to a hit.
        if (!EmailAddress.IsValid(email))
        {
            return Result.Success();
        }

        var now = clock.UtcNow;

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Email == email && candidate.Status == UserStatus.Active,
            cancellationToken);
        if (user is null)
        {
            return Result.Success();
        }

        // The sliding window counts reset issuances over the indexed
        // (user_id, purpose, created_at); at the limit, stop silently (still
        // the same success). Same guard the verify-email resend uses.
        var windowStart = now - PasswordResetPolicy.IssuanceWindow;
        var issuedInWindow = await db.OneTimeTokens.CountAsync(
            candidate => candidate.UserId == user.Id
                && candidate.Purpose == OneTimeTokenPurpose.ResetPassword
                && candidate.CreatedAt > windowStart,
            cancellationToken);
        if (issuedInWindow >= PasswordResetPolicy.IssuancesPerWindow)
        {
            return Result.Success();
        }

        var (row, rawToken) = PasswordResetPolicy.IssueResetPasswordToken(user.Id, now);
        db.OneTimeTokens.Add(row);
        await db.SaveChangesAsync(cancellationToken);

        // Post-save best-effort dispatch, the same hook as the verify-email
        // resend: the raw token is in hand here and the privacy rule keeps
        // it off the domain_events spine. A send failure must not fail the
        // request - the token is persisted and a later forgot-password
        // re-mints. No outbox event: there is no state change worth one, and
        // the reset token must never reach the event spine.
        try
        {
            await resetEmail.SendPasswordResetEmailAsync(user.Email, rawToken, cancellationToken);
        }
        catch (Exception exception)
        {
            PasswordResetEmailLog.DispatchFailed(logger, exception);
        }

        return Result.Success();
    }
}
