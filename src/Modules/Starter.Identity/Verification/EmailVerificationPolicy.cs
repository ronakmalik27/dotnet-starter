using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.SharedKernel;

namespace Starter.Identity.Verification;

/// <summary>
/// The FR-AUTH-02 numbers in one place, plus the verify_email token
/// factory. Tokens are 24-hour single-use (SRS 5.1); the account-level
/// soft deadline is 7 days from registration (doc 03 flow A5); resend is
/// limited to 3 per hour per account (doc 10 4.6).
/// </summary>
internal static class EmailVerificationPolicy
{
    /// <summary>Verify-email token TTL (FR-AUTH-02: 24 h).</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(24);

    /// <summary>The soft write-lock deadline (FR-AUTH-02: 7 days).</summary>
    public static readonly TimeSpan SoftDeadline = TimeSpan.FromDays(7);

    /// <summary>Verify-email issuances allowed per window (doc 10 4.6: 3/h).</summary>
    public const int IssuancesPerWindow = 3;

    /// <summary>The resend rate-limit window (doc 10 4.6: per hour).</summary>
    public static readonly TimeSpan IssuanceWindow = TimeSpan.FromHours(1);

    /// <summary>
    /// Mints a verify_email one_time_tokens row. The raw token is returned
    /// to the caller for the delivery channel and exists nowhere else -
    /// the row keeps only the hash (doc 10 4.4).
    /// </summary>
    public static (OneTimeToken Row, string RawToken) IssueVerifyEmailToken(Guid userId, DateTimeOffset now)
    {
        var rawToken = OneTimeTokenSecrets.NewToken();
        var row = new OneTimeToken
        {
            Id = Ids.NewId(now),
            UserId = userId,
            Purpose = OneTimeTokenPurpose.VerifyEmail,
            TokenHash = OneTimeTokenSecrets.Hash(rawToken),
            ExpiresAt = now + TokenLifetime,
            CreatedAt = now,
        };
        return (row, rawToken);
    }
}
