using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Identity.Domain;
using Starter.Identity.Verification;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Provisioning;

/// <summary>
/// The write side of the <see cref="Starter.Platform.Auth.IUserProvisioner"/> seam
/// (sso-and-scim.md section 5): resolves an email to a global user id, creating the
/// user when absent. It exists for SCIM provisioning, whose directory push has no
/// upstream account-creation step - unlike SSO, which creates the user AS it
/// authenticates them. Users are global (no tenant, no RLS), so this is a plain
/// read/insert on the request connection - NOT the bypass path.
/// <para>
/// The created user is BORN UNVERIFIED and PASSWORDLESS: it has an email but no
/// proven address and no credential. That is deliberate and load-bearing. A SCIM
/// shell must not be born verified, because the tenant member's FIRST real SSO
/// login then claims the shell through the existing account-linking table: an
/// unverified account resolves to <c>ClaimUnverifiedAccount</c>
/// (<see cref="GoogleSignIn.GoogleLinking"/>), which links the SSO method with no
/// new code path, whereas a verified account with no live confirmation would resolve
/// to <c>ConfirmationRequired</c> (409) and lock the member out of their own shell.
/// </para>
/// </summary>
internal sealed class UserProvisioner(IdentityDbContext db, OutboxWriter outbox, Clock clock)
{
    /// <summary>The provisioning-source marker on the registration event's payload (not an auth-method kind - a SCIM shell has none yet).</summary>
    private const string ProvisioningMethod = "scim";

    public async Task<Guid> EnsureProvisionedUserAsync(string email, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        email = email.Trim();

        // Two attempts: a concurrent provision of the same email races the unique
        // (citext) email index; the loser catches the violation, clears its stale
        // tracked state, and re-reads the winner's row (the GoogleSignInHandler
        // precedent). Idempotent on email by construction.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0)
            {
                db.ChangeTracker.Clear();
            }

            // Match ANY user holding the email (not only active): the email index is
            // global, so a shell already created by an earlier provision - or a real
            // account - must be re-read, never duplicated.
            var existing = await db.Users
                .AsNoTracking()
                .Where(user => user.Email == email)
                .Select(user => (Guid?)user.Id)
                .SingleOrDefaultAsync(cancellationToken);
            if (existing is Guid existingId)
            {
                return existingId;
            }

            var now = clock.UtcNow;
            var newUser = new User
            {
                Id = Ids.NewId(now),
                Email = email,
                // Active status but UNVERIFIED email: the shell is usable as a member
                // record, and its first SSO login proves the address and claims it.
                Status = UserStatus.Active,
                EmailVerifiedAt = null,
                TokenVersion = 1,
                // The same soft deadline a self-registered account starts with; the
                // account cannot write until verified (the vrf capability gate).
                VerificationDeadlineAt = now + EmailVerificationPolicy.SoftDeadline,
                CreatedAt = now,
            };

            // The create opens a transaction (the RegisterHandler idiom): OutboxWriter
            // stamps and enqueues the event inside the same business transaction as the
            // user insert, and requires one to be open.
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            db.Users.Add(newUser);

            // No auth-methods row: the shell is passwordless and carries no SSO
            // subject yet. A credential attaches when the member first signs in.
            await outbox.EnqueueAsync(
                db, IdentityEvents.UserRegistered(newUser.Id, ProvisioningMethod, now), cancellationToken);

            try
            {
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return newUser.Id;
            }
            catch (DbUpdateException exception) when (IsUniqueViolation(exception))
            {
                // A concurrent provision won the email index; the await using disposes
                // (rolls back) this transaction. Fall through to the retry, which
                // re-reads the winner's id.
            }
        }

        // The retry re-read must find the row the racing insert committed.
        var raced = await db.Users
            .AsNoTracking()
            .Where(user => user.Email == email)
            .Select(user => (Guid?)user.Id)
            .SingleOrDefaultAsync(cancellationToken);
        return raced ?? throw new InvalidOperationException(
            "The provisioned user could not be resolved after a unique-email race.");
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
