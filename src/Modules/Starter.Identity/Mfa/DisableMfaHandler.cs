using Microsoft.EntityFrameworkCore;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// Disable MFA (mfa-totp.md section 7). Authenticated + a fresh TOTP or
/// recovery code: re-verifying the second factor proves it is really the
/// enrolled user (not a hijacked session) turning MFA off. On success, delete
/// the mfa_credentials row and all recovery codes, emit identity.mfa.disabled,
/// and login reverts to one step. A wrong code does not disable.
/// </summary>
internal sealed class DisableMfaHandler(
    IdentityDbContext db,
    MfaSecretProtector protector,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error NotEnabled = new(
        ErrorKind.Validation,
        "auth.mfa_not_enabled",
        "MFA is not enabled on this account.");

    private static readonly Error CodeInvalid = new(
        ErrorKind.Validation,
        "auth.mfa_code_invalid",
        "The verification code is incorrect.");

    public async Task<Result> HandleAsync(Guid userId, string code, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);

        var credential = await db.MfaCredentials.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId && candidate.ConfirmedAt != null,
            cancellationToken);
        if (credential is null)
        {
            return Result.Failure(NotEnabled);
        }

        var now = clock.UtcNow;

        var valid = false;
        try
        {
            var secret = Base32.Decode(protector.Unprotect(credential.SecretEncrypted));
            valid = Totp.Verify(secret, code, Totp.CurrentStep(now), credential.LastStep, out _);
        }
        catch (MfaSecretUnprotectException)
        {
            // The key ring cannot decrypt the secret; only a recovery code can
            // disable (the documented key-ring-independent fallback).
        }

        if (!valid)
        {
            // A TOTP-shaped code normalizes to a non-recovery base32 string;
            // skip the lookup when it is empty rather than hash an empty string.
            var normalized = RecoveryCodes.Normalize(code);
            if (normalized.Length != 0)
            {
                var hash = RecoveryCodes.Hash(normalized);
                valid = await db.MfaRecoveryCodes.AnyAsync(
                    row => row.UserId == userId && row.CodeHash == hash && row.UsedAt == null,
                    cancellationToken);
            }
        }

        if (!valid)
        {
            return Result.Failure(CodeInvalid);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.MfaRecoveryCodes.Where(row => row.UserId == userId).ExecuteDeleteAsync(cancellationToken);
        await db.MfaCredentials.Where(row => row.UserId == userId).ExecuteDeleteAsync(cancellationToken);
        await outbox.EnqueueAsync(db, IdentityEvents.MfaDisabled(userId, now), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }
}
