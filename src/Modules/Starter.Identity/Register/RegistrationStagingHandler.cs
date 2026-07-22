using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.Identity.Verification;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Identity.Register;

/// <summary>
/// The registration-staging seam for atomic self-serve tenant provisioning. It
/// stages a new account (User + password AuthMethod + verify-email token) and
/// enqueues UserRegistered ON A CALLER-OWNED transaction, and does NOT commit -
/// the tenancy provisioner owns the single commit that lands the user, the
/// tenant, and the owner membership together, so a failure leaves neither.
/// <para>
/// It reuses exactly the same validation, Argon2 hashing, and token-minting
/// primitives as <see cref="RegisterHandler"/> (EmailAddress, PasswordPolicy,
/// PasswordHasher, EmailVerificationPolicy), so the two flows cannot drift. What
/// differs is transaction ownership and the enumeration contract: on an
/// already-registered email it reports that WITHOUT creating anything and
/// enqueues no event (the provisioner rolls the whole unit back), so nothing
/// leaks and the caller returns the same generic success as a fresh signup.
/// </para>
/// <para>
/// Its IdentityDbContext is built with the no-tenant context
/// (<see cref="ITenantContext.None"/>), so UserRegistered is stamped
/// tenant_id = null: a user is global, not tenant-owned. It builds that context
/// on the caller's shared connection and enlists the caller's transaction - the
/// same enlist-a-second-context-on-one-connection pattern OutboxWriter uses.
/// </para>
/// </summary>
internal sealed class RegistrationStagingHandler(PasswordPolicy policy, OutboxWriter outbox, Clock clock)
{
    public async Task<Result<StagedRegistration>> HandleAsync(
        DbConnection sharedConnection,
        IDbContextTransaction sharedTransaction,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sharedConnection);
        ArgumentNullException.ThrowIfNull(sharedTransaction);
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        email = email.Trim();
        if (!EmailAddress.IsValid(email))
        {
            return Result.Failure<StagedRegistration>(new Error(
                ErrorKind.Validation, "auth.email_invalid", "The email address is not valid."));
        }

        var policyCheck = policy.Check(password);
        if (policyCheck.IsFailure)
        {
            return Result.Failure<StagedRegistration>(policyCheck.Error);
        }

        var now = clock.UtcNow;

        // Hash before the existence branch: both outcomes pay the same Argon2
        // cost, so response timing does not distinguish a fresh email from one
        // that already has an account (the same rule RegisterHandler follows).
        var passwordHash = PasswordHasher.Hash(password);

        // Enlist a fresh IdentityDbContext on the caller's connection and
        // transaction. No-tenant context, so UserRegistered is a global event
        // (tenant_id = null) and the interceptor sets no GUC for this context.
        var options = StarterDbContextOptions.ForConnection<IdentityDbContext>(sharedConnection).Options;
        await using var db = new IdentityDbContext(options, ITenantContext.None);
        await db.Database.UseTransactionAsync(sharedTransaction.GetDbTransaction(), cancellationToken);

        var existing = await db.Users.SingleOrDefaultAsync(user => user.Email == email, cancellationToken);
        if (existing is not null)
        {
            // Report existence without staging anything. No reattempt event is
            // enqueued: the provisioner rolls back the whole unit, so any event
            // would be discarded anyway, and a "was this you?" notice would ride
            // the normal register flow, not signup.
            return Result.Success(StagedRegistration.AlreadyExists);
        }

        var newUser = new User
        {
            Id = Ids.NewId(now),
            Email = email,
            Status = UserStatus.Active,
            TokenVersion = 1,
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

        // The verify-email token issues with the account. The raw token is
        // returned to the provisioner for the post-commit email; it is never
        // persisted raw and never rides the outbox.
        var (verificationToken, rawToken) = EmailVerificationPolicy.IssueVerifyEmailToken(newUser.Id, now);
        db.OneTimeTokens.Add(verificationToken);

        await outbox.EnqueueAsync(
            db, IdentityEvents.UserRegistered(newUser.Id, AuthMethodKind.Password, now), cancellationToken);

        // Stage the writes on the shared transaction; the provisioner commits.
        await db.SaveChangesAsync(cancellationToken);

        return Result.Success(StagedRegistration.Created(newUser.Id, rawToken));
    }
}
