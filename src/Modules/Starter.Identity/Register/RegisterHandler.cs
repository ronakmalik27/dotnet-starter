using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.Identity.Verification;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Register;

/// <summary>
/// Registration. The no-account-enumeration contract shapes the
/// whole flow: an existing email returns the exact same success as a fresh
/// one, the address owner gets a "was this you?" notice via the outbox,
/// and the Argon2 hash is computed on both paths so response timing does
/// not distinguish them either.
/// </summary>
internal sealed class RegisterHandler(
    IdentityDbContext db,
    PasswordPolicy policy,
    OutboxWriter outbox,
    VerificationEmailComposer verificationEmail,
    ILogger<RegisterHandler> logger,
    Clock clock)
{
    public async Task<Result> HandleAsync(string email, string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        email = email.Trim();
        if (!EmailAddress.IsValid(email))
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "auth.email_invalid",
                "The email address is not valid."));
        }

        var policyCheck = policy.Check(password);
        if (policyCheck.IsFailure)
        {
            return policyCheck;
        }

        var now = clock.UtcNow;

        // Hash before branching: both outcomes pay the same Argon2 cost
        // (timing must not leak account existence).
        var passwordHash = PasswordHasher.Hash(password);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var existing = await db.Users
            .SingleOrDefaultAsync(user => user.Email == email, cancellationToken);
        if (existing is not null)
        {
            await outbox.EnqueueAsync(
                db, IdentityEvents.RegistrationReattempted(existing.Id, now), cancellationToken);
            // EnqueueAsync only stages the event/outbox rows on the
            // context; without SaveChangesAsync here the "was this you?"
            // notice never reaches the database and the commit below
            // would persist nothing.
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Success();
        }

        var newUser = new User
        {
            Id = Ids.NewId(now),
            Email = email,
            Status = UserStatus.Active,
            TokenVersion = 1,
            // The 7-day soft deadline starts at registration, uniformly
            // for every account. Until verification, the account cannot
            // write at all - one rule, no separate branch to get wrong.
            VerificationDeadlineAt = now + EmailVerificationPolicy.SoftDeadline,
            CreatedAt = now,
        };
        db.Users.Add(newUser);
        db.AuthMethods.Add(new AuthMethod
        {
            Id = Ids.NewId(now),
            UserId = newUser.Id,
            Kind = AuthMethodKind.Password,
            PasswordHash = passwordHash,
            CreatedAt = now,
        });

        // The first verify_email token issues with the account
        // (24 h, single-use). The raw token is kept in hand for the
        // post-commit email dispatch below; the privacy rule keeps raw
        // secrets off the domain_events spine, so it never rides the outbox.
        var (verificationToken, rawToken) = EmailVerificationPolicy.IssueVerifyEmailToken(newUser.Id, now);
        db.OneTimeTokens.Add(verificationToken);

        await outbox.EnqueueAsync(
            db, IdentityEvents.UserRegistered(newUser.Id, AuthMethodKind.Password, now), cancellationToken);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // Two same-email registrations raced and this one lost the
            // unique index. Same success, per the enumeration rule; no
            // notice event - the winning insert is milliseconds old and
            // unverified, so there is no established owner to warn yet. No
            // email either: this path never created the account.
            return Result.Success();
        }

        // New account committed: send the verification email best-effort.
        // Only this new-account path sends - the existing-account and
        // unique-violation-race paths above return without a send, which is
        // what keeps the endpoint enumeration-safe. A failure here must not
        // fail registration: the account exists and the resend endpoint
        // recovers. A production system would move dispatch to a
        // transactional email-outbox for delivery guarantees and uniform
        // timing; this inline post-commit send is the starter-appropriate
        // version, at the hook where the raw token is still in hand.
        try
        {
            await verificationEmail.SendVerificationEmailAsync(email, rawToken, cancellationToken);
        }
        catch (Exception exception)
        {
            VerificationEmailLog.DispatchFailed(logger, exception);
        }

        return Result.Success();
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
