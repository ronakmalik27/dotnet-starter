using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.Identity.Tokens;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.PasswordReset;

/// <summary>
/// Reset-password: POST /auth/reset-password { token, newPassword }. Mirrors
/// VerifyEmailHandler's atomic single-use consume - a lookup outside the
/// transaction, then a guarded ExecuteUpdateAsync on used_at so two racing
/// submissions of the same token cannot both win. On a live token the new
/// password replaces (or, for a password-less Google-only account, creates)
/// the password method, re-enables a method disabled by the OIDC
/// unverified-claim path, bumps the user's token version (soft-revoking
/// every session - enforced at refresh), and emits
/// identity.password.changed. Unknown, used, and expired tokens all return
/// one generic Validation error, exactly like verify-email.
/// </summary>
internal sealed class ResetPasswordHandler(
    IdentityDbContext db,
    PasswordPolicy policy,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error InvalidToken = new(
        ErrorKind.Validation,
        "auth.reset_token_invalid",
        "This password-reset link is invalid, already used, or expired.");

    public async Task<Result> HandleAsync(string token, string newPassword, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(newPassword);

        if (token.Length == 0)
        {
            return Result.Failure(InvalidToken);
        }

        var now = clock.UtcNow;
        var tokenHash = OneTimeTokenSecrets.Hash(token);

        // Lookup outside the transaction, same shape as VerifyEmailHandler:
        // garbage tokens never pay for a BEGIN/ROLLBACK round trip.
        var row = await db.OneTimeTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.TokenHash == tokenHash
                    && candidate.Purpose == OneTimeTokenPurpose.ResetPassword,
                cancellationToken);
        if (row is null || row.UsedAt is not null || row.ExpiresAt <= now)
        {
            return Result.Failure(InvalidToken);
        }

        // Policy-check before consuming: a weak password must not burn the
        // single-use token. The caller supplied both the token and the
        // password, so checking the password first leaks nothing and lets a
        // legitimate user retry with a stronger one on the same link.
        var policyCheck = policy.Check(newPassword);
        if (policyCheck.IsFailure)
        {
            return policyCheck;
        }

        // Hash outside the transaction (Argon2 is deliberately slow; holding
        // a pooled connection across it is the pool-exhaustion risk the
        // login path avoids the same way).
        var newHash = PasswordHasher.Hash(newPassword);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Consume-if-still-live, atomically: the single-use guarantee lives
        // in this WHERE clause, not in the read above. The loser of a race
        // sees zero rows and gets the same generic failure.
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

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == row.UserId && candidate.Status == UserStatus.Active,
            cancellationToken);
        if (user is null)
        {
            // The token pointed at a gone or inert account. Same generic
            // answer; the rollback leaves the token unconsumed, which is
            // harmless (it can never resolve to an active account).
            return Result.Failure(InvalidToken);
        }

        var method = await db.AuthMethods.SingleOrDefaultAsync(
            candidate => candidate.UserId == user.Id && candidate.Kind == AuthMethodKind.Password,
            cancellationToken);
        if (method is null)
        {
            // A password-less (e.g. Google-only) account sets its first
            // password via reset - a new auth_methods row.
            db.AuthMethods.Add(new AuthMethod
            {
                Id = Ids.NewId(now),
                UserId = user.Id,
                Kind = AuthMethodKind.Password,
                PasswordHash = newHash,
                CreatedAt = now,
            });
        }
        else
        {
            // Replace the hash and clear any disable: a reset is exactly
            // what re-enables a password the OIDC unverified-claim path
            // distrusted.
            method.PasswordHash = newHash;
            method.DisabledAt = null;
        }

        // Bump ver: every existing session carries the old version, so its
        // next refresh fails. Access tokens age out within their short TTL.
        user.TokenVersion += 1;
        await outbox.EnqueueAsync(db, IdentityEvents.PasswordChanged(user.Id, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }
}
