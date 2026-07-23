using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// MFA confirmation (mfa-totp.md section 4). Authenticated + a fresh current
/// password (step-up) + a code from the authenticator: verify the code against
/// the pending secret, and on success set confirmed_at, promote the pending
/// secret, generate the recovery codes (shown ONCE, stored hashed), and emit
/// identity.mfa.enabled. Confirming proves the authenticator actually works
/// before the user is locked into needing it. A wrong code does not confirm.
/// </summary>
internal sealed class ConfirmMfaHandler(
    IdentityDbContext db,
    MfaSecretProtector protector,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error CodeInvalid = new(
        ErrorKind.Validation,
        "auth.mfa_code_invalid",
        "The verification code is incorrect.");

    private static readonly Error NotPending = new(
        ErrorKind.Validation,
        "auth.mfa_not_pending",
        "There is no pending MFA enrollment to confirm; start enrollment first.");

    private static readonly Error SecretUnavailable = new(
        ErrorKind.Validation,
        "auth.mfa_secret_unavailable",
        "The pending MFA secret could not be read; start enrollment again.");

    public async Task<Result<MfaRecoveryCodes>> HandleAsync(
        Guid userId,
        string currentPassword,
        string code,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(code);

        var stepUp = await StepUpPassword.VerifyAsync(db, userId, currentPassword, cancellationToken);
        if (stepUp.IsFailure)
        {
            return stepUp.Error;
        }

        var credential = await db.MfaCredentials.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId, cancellationToken);
        if (credential is null)
        {
            return NotPending;
        }

        // The secret being confirmed: a re-enroll confirms its PENDING secret;
        // an initial enroll confirms the (still-unconfirmed) active secret.
        var targetCiphertext = credential.PendingSecretEncrypted
            ?? (credential.ConfirmedAt is null ? credential.SecretEncrypted : null);
        if (targetCiphertext is null)
        {
            return NotPending;
        }

        byte[] secret;
        try
        {
            secret = Base32.Decode(protector.Unprotect(targetCiphertext));
        }
        catch (MfaSecretUnprotectException)
        {
            return SecretUnavailable;
        }

        var now = clock.UtcNow;
        if (!Totp.Verify(secret, code, Totp.CurrentStep(now), lastAcceptedStep: null, out var matchedStep))
        {
            return CodeInvalid;
        }

        var codes = RecoveryCodes.Generate();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Promote the confirmed secret and enable MFA. Record the confirming
        // code's step so it cannot be replayed as a login code.
        credential.SecretEncrypted = targetCiphertext;
        credential.PendingSecretEncrypted = null;
        credential.ConfirmedAt = now;
        credential.LastStep = matchedStep;
        credential.FailedAttempts = 0;
        credential.LockedUntil = null;

        // Fresh secret, fresh codes: drop any prior set so a re-enroll's codes
        // never verify against the new secret's account.
        await db.MfaRecoveryCodes.Where(row => row.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);
        foreach (var (_, hash) in codes)
        {
            db.MfaRecoveryCodes.Add(new MfaRecoveryCode
            {
                Id = Ids.NewId(now),
                UserId = userId,
                CodeHash = hash,
                CreatedAt = now,
            });
        }

        await outbox.EnqueueAsync(db, IdentityEvents.MfaEnabled(userId, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new MfaRecoveryCodes([.. codes.Select(code => code.Display)]);
    }
}
