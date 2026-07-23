using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// MFA enrollment (mfa-totp.md section 4). Authenticated + a fresh current
/// password (step-up): generate a 20-byte secret, store it ENCRYPTED with
/// confirmed_at = null, and return the otpauth URI + base32 secret (shown
/// ONCE) so the client can render a QR. This does NOT yet enable MFA - confirm
/// does. A re-enroll while already confirmed writes a PENDING secret and leaves
/// the active secret and its confirmed state untouched, so a half-finished
/// re-enroll never locks the user out.
/// </summary>
internal sealed class EnrollMfaHandler(
    IdentityDbContext db,
    MfaSecretProtector protector,
    Clock clock)
{
    private const int SecretBytes = 20;

    public async Task<Result<MfaEnrollment>> HandleAsync(
        Guid userId,
        string currentPassword,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);

        var stepUp = await StepUpPassword.VerifyAsync(db, userId, currentPassword, cancellationToken);
        if (stepUp.IsFailure)
        {
            return stepUp.Error;
        }

        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == userId && candidate.Status == UserStatus.Active,
            cancellationToken);
        if (user is null)
        {
            return new Error(
                ErrorKind.Unauthorized,
                "auth.unknown_user",
                "The authenticated account no longer exists.");
        }

        var now = clock.UtcNow;
        var base32Secret = Base32.Encode(RandomNumberGenerator.GetBytes(SecretBytes));
        var ciphertext = protector.Protect(base32Secret);

        var existing = await db.MfaCredentials.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId, cancellationToken);
        if (existing is null)
        {
            db.MfaCredentials.Add(new MfaCredential
            {
                UserId = userId,
                SecretEncrypted = ciphertext,
                ConfirmedAt = null,
                CreatedAt = now,
            });
        }
        else if (existing.ConfirmedAt is null)
        {
            // Enrollment not yet confirmed: replace the pending secret in place.
            existing.SecretEncrypted = ciphertext;
            existing.PendingSecretEncrypted = null;
            existing.LastStep = null;
        }
        else
        {
            // Already confirmed: this is a re-enroll. Stage the new secret as
            // PENDING and leave the active secret + confirmed_at intact, so MFA
            // stays on the old secret until a new confirm promotes this one.
            existing.PendingSecretEncrypted = ciphertext;
        }

        await db.SaveChangesAsync(cancellationToken);

        return new MfaEnrollment(OtpAuthUri.Build(user.Email, base32Secret), base32Secret);
    }
}
