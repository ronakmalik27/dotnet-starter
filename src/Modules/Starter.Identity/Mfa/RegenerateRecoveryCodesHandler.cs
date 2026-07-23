using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// Regenerate recovery codes (mfa-totp.md section 6). Authenticated + a fresh
/// TOTP code: REPLACE all prior codes with a new set of 10 (shown ONCE, stored
/// hashed), so a user who suspects a leaked list can rotate. The fresh code is
/// replay-guarded like a login code, so a captured code cannot be replayed to
/// rotate a victim's codes.
/// </summary>
internal sealed class RegenerateRecoveryCodesHandler(
    IdentityDbContext db,
    MfaSecretProtector protector,
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

    public async Task<Result<MfaRecoveryCodes>> HandleAsync(
        Guid userId,
        string code,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);

        var credential = await db.MfaCredentials.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId && candidate.ConfirmedAt != null,
            cancellationToken);
        if (credential is null)
        {
            return NotEnabled;
        }

        var now = clock.UtcNow;

        byte[] secret;
        try
        {
            secret = Base32.Decode(protector.Unprotect(credential.SecretEncrypted));
        }
        catch (MfaSecretUnprotectException)
        {
            return CodeInvalid;
        }

        if (!Totp.Verify(secret, code, Totp.CurrentStep(now), credential.LastStep, out var matchedStep))
        {
            return CodeInvalid;
        }

        var codes = RecoveryCodes.Generate();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Advance the replay guard atomically; a replayed code sees zero rows.
        var advanced = await db.MfaCredentials
            .Where(row => row.UserId == userId && (row.LastStep == null || row.LastStep < matchedStep))
            .ExecuteUpdateAsync(
                set => set.SetProperty(row => row.LastStep, matchedStep),
                cancellationToken);
        if (advanced != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return CodeInvalid;
        }

        await db.MfaRecoveryCodes.Where(row => row.UserId == userId).ExecuteDeleteAsync(cancellationToken);
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

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new MfaRecoveryCodes([.. codes.Select(code => code.Display)]);
    }
}
