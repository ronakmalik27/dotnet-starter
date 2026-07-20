using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.SharedKernel;

namespace Starter.Identity.PasswordReset;

/// <summary>
/// The password-reset numbers in one place, plus the reset_password token
/// factory. Tokens are 1-hour single-use (shorter than the 24-hour
/// verify-email token: a reset link is a credential-change lever, so it
/// lives briefly). Issuance is limited to 3 per hour per account, mirroring
/// the verify-email resend guard, so the forgot-password endpoint cannot be
/// used to flood an account's mailbox.
/// </summary>
internal static class PasswordResetPolicy
{
    /// <summary>Reset-token TTL (1 h).</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(1);

    /// <summary>Reset issuances allowed per window (3/h).</summary>
    public const int IssuancesPerWindow = 3;

    /// <summary>The issuance rate-limit window (per hour).</summary>
    public static readonly TimeSpan IssuanceWindow = TimeSpan.FromHours(1);

    /// <summary>
    /// Mints a reset_password one_time_tokens row. The raw token is returned
    /// to the caller for the delivery channel and exists nowhere else - the
    /// row keeps only the hash, exactly like the verify-email token.
    /// </summary>
    public static (OneTimeToken Row, string RawToken) IssueResetPasswordToken(Guid userId, DateTimeOffset now)
    {
        var rawToken = OneTimeTokenSecrets.NewToken();
        var row = new OneTimeToken
        {
            Id = Ids.NewId(now),
            UserId = userId,
            Purpose = OneTimeTokenPurpose.ResetPassword,
            TokenHash = OneTimeTokenSecrets.Hash(rawToken),
            ExpiresAt = now + TokenLifetime,
            CreatedAt = now,
        };
        return (row, rawToken);
    }
}
