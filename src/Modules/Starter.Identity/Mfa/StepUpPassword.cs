using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Passwords;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// The step-up credential proof shared by enroll and confirm (mfa-totp.md
/// section 4): enabling MFA is security-equivalent to changing a password, so
/// both require a FRESH proof of the current password, not just a session. An
/// attacker holding only a hijacked access token cannot enroll their own
/// secret. The generic "current password did not check out" answer is the same
/// one ChangePassword uses, with the Argon2 cost burned on the miss paths
/// (VerifyDummy) so timing does not distinguish them. A passwordless
/// (Google-only) account has no password to prove, so it lands on the generic
/// failure - it must set a password first (a documented step-up path).
/// </summary>
internal static class StepUpPassword
{
    /// <summary>
    /// The one generic answer for every "current password does not check out"
    /// case - absent password method, disabled method, or a wrong password.
    /// Validation, so the endpoint names it on the currentPassword field.
    /// </summary>
    public static readonly Error IncorrectCurrentPassword = new(
        ErrorKind.Validation,
        "auth.current_password_incorrect",
        "The current password is incorrect.");

    public static async Task<Result> VerifyAsync(
        IdentityDbContext db,
        Guid userId,
        string currentPassword,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(currentPassword);

        var method = await db.AuthMethods.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId && candidate.Kind == AuthMethodKind.Password,
            cancellationToken);

        if (method?.PasswordHash is null || method.DisabledAt is not null)
        {
            // No usable password credential (Google-only account, or a
            // disabled password). Burn the same Argon2 cost as a real verify so
            // timing does not distinguish, and answer the generic error.
            PasswordHasher.VerifyDummy(currentPassword);
            return Result.Failure(IncorrectCurrentPassword);
        }

        return PasswordHasher.Verify(currentPassword, method.PasswordHash)
            ? Result.Success()
            : Result.Failure(IncorrectCurrentPassword);
    }
}
