using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.ChangePassword;

/// <summary>
/// The change-password slice of PUT /auth/password: the authenticated
/// caller supplies the current password and a new one. This is the case
/// SetPasswordHandler deferred (it owned only the first-password path). The
/// current password is verified against the existing password method's hash
/// with the same Argon2 verify the login path uses; on success the hash is
/// rotated, the user's token version is bumped (soft-revoking every other
/// session - ver is enforced at refresh), and identity.password.changed is
/// emitted on the outbox in the same transaction.
/// </summary>
internal sealed class ChangePasswordHandler(
    IdentityDbContext db,
    PasswordPolicy policy,
    OutboxWriter outbox,
    Clock clock)
{
    /// <summary>
    /// One generic answer for every "current password does not check out"
    /// case - absent password method, disabled method, or a wrong password
    /// - so the response never distinguishes them. Validation, so the
    /// endpoint carries a clear message on the currentPassword field.
    /// </summary>
    private static readonly Error IncorrectCurrentPassword = new(
        ErrorKind.Validation,
        "auth.current_password_incorrect",
        "The current password is incorrect.");

    public async Task<Result> HandleAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);

        var policyCheck = policy.Check(newPassword);
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

        var method = await db.AuthMethods.SingleOrDefaultAsync(
            candidate => candidate.UserId == user.Id && candidate.Kind == AuthMethodKind.Password,
            cancellationToken);

        if (method?.PasswordHash is null || method.DisabledAt is not null)
        {
            // No usable password credential to change (Google-only account,
            // or a password disabled by the OIDC claim - re-enabled only by
            // a reset). Burn the same Argon2 cost as a real verify so timing
            // does not distinguish, and answer the generic error.
            PasswordHasher.VerifyDummy(currentPassword);
            return Result.Failure(IncorrectCurrentPassword);
        }

        if (!PasswordHasher.Verify(currentPassword, method.PasswordHash))
        {
            return Result.Failure(IncorrectCurrentPassword);
        }

        // The credential is proven. Hash the new password OUTSIDE the
        // transaction (Argon2 is deliberately slow; holding a pooled
        // connection across it is the pool-exhaustion risk LoginHandler
        // avoids the same way).
        var newHash = PasswordHasher.Hash(newPassword);
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        method.PasswordHash = newHash;
        // Bump ver: every existing session carries the old version, so its
        // next refresh fails. Access tokens age out within their short TTL.
        user.TokenVersion += 1;
        await outbox.EnqueueAsync(db, IdentityEvents.PasswordChanged(user.Id, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }
}
