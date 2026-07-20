using Microsoft.EntityFrameworkCore;
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
        // (24 h, single-use). The raw token is dropped for
        // now: email dispatch is the notifications story's channel,
        // and the privacy rule keeps raw secrets off the
        // domain_events spine - the dispatch hook slots in here, where
        // the raw token is still in hand, when that story lands. Until
        // then the resend endpoint is the way to mint a fresh one.
        var (verificationToken, _) = EmailVerificationPolicy.IssueVerifyEmailToken(newUser.Id, now);
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
            // unverified, so there is no established owner to warn yet.
            return Result.Success();
        }

        return Result.Success();
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
