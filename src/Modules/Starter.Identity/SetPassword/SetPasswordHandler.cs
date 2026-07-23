using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.SetPassword;

/// <summary>
/// The dual-method slice of PUT /auth/password: a passwordless
/// (Google-created) account sets its FIRST password and becomes
/// dual-method - a second auth_methods row, same list model (deferred-
/// readiness). Changing an existing password is a separate flow (current
/// password, session revocation) and stays 501 until that story lands;
/// this handler owns only the no-password-yet case.
/// </summary>
internal sealed class SetPasswordHandler(
    IdentityDbContext db,
    PasswordPolicy policy,
    OutboxWriter outbox,
    Clock clock)
{
    /// <summary>
    /// A password method already exists (enabled or disabled): replacing
    /// it needs a change-password or reset flow, neither of
    /// which has landed. The endpoint layer maps this code to 501
    /// starter:not-implemented, the precedent for documented-but-
    /// unshipped capability.
    /// </summary>
    private static readonly Error ChangeNotImplemented = new(
        ErrorKind.Conflict,
        "auth.password_change_not_implemented",
        "This account already has a password; changing it lands with the change-password flow.");

    public async Task<Result> HandleAsync(Guid userId, string newPassword, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(newPassword);

        var policyCheck = await policy.CheckAsync(newPassword, cancellationToken);
        if (policyCheck.IsFailure)
        {
            return policyCheck;
        }

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == userId && candidate.Status == UserStatus.Active,
            cancellationToken);
        if (user is null)
        {
            return Result.Failure(new Error(
                ErrorKind.Unauthorized,
                "auth.unknown_user",
                "The authenticated account no longer exists."));
        }

        var existing = await db.AuthMethods.SingleOrDefaultAsync(
            method => method.UserId == user.Id && method.Kind == AuthMethodKind.Password,
            cancellationToken);
        if (existing is not null)
        {
            return Result.Failure(ChangeNotImplemented);
        }

        var now = clock.UtcNow;

        // The transaction opens before the enqueue: the outbox write joins
        // the open business transaction (write rule).
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        db.AuthMethods.Add(new AuthMethod
        {
            Id = Ids.NewId(now),
            UserId = user.Id,
            Kind = AuthMethodKind.Password,
            PasswordHash = PasswordHasher.Hash(newPassword),
            CreatedAt = now,
        });
        await outbox.EnqueueAsync(db, IdentityEvents.PasswordChanged(user.Id, now), cancellationToken);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // Two concurrent first-password sets raced on unique
            // (user_id, kind); the loser's truthful answer is the same as
            // finding the winner's row up front.
            return Result.Failure(ChangeNotImplemented);
        }

        return Result.Success();
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
