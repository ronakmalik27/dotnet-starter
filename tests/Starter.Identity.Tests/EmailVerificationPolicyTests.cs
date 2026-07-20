using Shouldly;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Identity.Verification;
using Starter.SharedKernel;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// The FR-AUTH-02 numbers and the verify_email token factory: 24-hour
/// single-use tokens, the 7-day soft deadline, 3/h resend. Deterministic
/// time throughout (doc 12 section 1: tests own time).
/// </summary>
public class EmailVerificationPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 15, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Numbers_MatchTheContract()
    {
        // FR-AUTH-02: 24 h token, 7-day soft deadline; doc 10 4.6: 3/h.
        EmailVerificationPolicy.TokenLifetime.ShouldBe(TimeSpan.FromHours(24));
        EmailVerificationPolicy.SoftDeadline.ShouldBe(TimeSpan.FromDays(7));
        EmailVerificationPolicy.IssuancesPerWindow.ShouldBe(3);
        EmailVerificationPolicy.IssuanceWindow.ShouldBe(TimeSpan.FromHours(1));
    }

    [Fact]
    public void IssueVerifyEmailToken_MintsA24HourVerifyEmailRow()
    {
        var userId = Ids.NewId(Now);

        var (row, rawToken) = EmailVerificationPolicy.IssueVerifyEmailToken(userId, Now);

        row.UserId.ShouldBe(userId);
        row.Purpose.ShouldBe(OneTimeTokenPurpose.VerifyEmail);
        row.CreatedAt.ShouldBe(Now);
        row.ExpiresAt.ShouldBe(Now.AddHours(24));
        row.UsedAt.ShouldBeNull();
        row.Payload.ShouldBeNull();
        rawToken.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void IssueVerifyEmailToken_StoresOnlyTheHash_NeverTheRawToken()
    {
        var (row, rawToken) = EmailVerificationPolicy.IssueVerifyEmailToken(Ids.NewId(Now), Now);

        row.TokenHash.ShouldBe(OneTimeTokenSecrets.Hash(rawToken));
        row.TokenHash.ShouldNotContain(rawToken);
    }

    [Fact]
    public void IssueVerifyEmailToken_MintsAFreshSecretEveryCall()
    {
        var userId = Ids.NewId(Now);

        var (firstRow, firstToken) = EmailVerificationPolicy.IssueVerifyEmailToken(userId, Now);
        var (secondRow, secondToken) = EmailVerificationPolicy.IssueVerifyEmailToken(userId, Now);

        firstToken.ShouldNotBe(secondToken);
        firstRow.TokenHash.ShouldNotBe(secondRow.TokenHash);
        firstRow.Id.ShouldNotBe(secondRow.Id);
    }
}
