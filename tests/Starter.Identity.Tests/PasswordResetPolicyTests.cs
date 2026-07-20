using Shouldly;
using Starter.Identity.Domain;
using Starter.Identity.PasswordReset;
using Starter.Identity.Tokens;
using Starter.SharedKernel;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// The password-reset numbers and the reset_password token factory: 1-hour
/// single-use tokens, 3/h issuance. Deterministic time throughout (tests own
/// time).
/// </summary>
public class PasswordResetPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 20, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Numbers_MatchTheContract()
    {
        // 1 h token; issuance limited to 3/h, mirroring the verify-email
        // resend guard.
        PasswordResetPolicy.TokenLifetime.ShouldBe(TimeSpan.FromHours(1));
        PasswordResetPolicy.IssuancesPerWindow.ShouldBe(3);
        PasswordResetPolicy.IssuanceWindow.ShouldBe(TimeSpan.FromHours(1));
    }

    [Fact]
    public void IssueResetPasswordToken_MintsA1HourResetPasswordRow()
    {
        var userId = Ids.NewId(Now);

        var (row, rawToken) = PasswordResetPolicy.IssueResetPasswordToken(userId, Now);

        row.UserId.ShouldBe(userId);
        row.Purpose.ShouldBe(OneTimeTokenPurpose.ResetPassword);
        row.CreatedAt.ShouldBe(Now);
        row.ExpiresAt.ShouldBe(Now.AddHours(1));
        row.UsedAt.ShouldBeNull();
        row.Payload.ShouldBeNull();
        rawToken.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void IssueResetPasswordToken_StoresOnlyTheHash_NeverTheRawToken()
    {
        var (row, rawToken) = PasswordResetPolicy.IssueResetPasswordToken(Ids.NewId(Now), Now);

        row.TokenHash.ShouldBe(OneTimeTokenSecrets.Hash(rawToken));
        row.TokenHash.ShouldNotContain(rawToken);
    }

    [Fact]
    public void IssueResetPasswordToken_MintsAFreshSecretEveryCall()
    {
        var userId = Ids.NewId(Now);

        var (firstRow, firstToken) = PasswordResetPolicy.IssueResetPasswordToken(userId, Now);
        var (secondRow, secondToken) = PasswordResetPolicy.IssueResetPasswordToken(userId, Now);

        firstToken.ShouldNotBe(secondToken);
        firstRow.TokenHash.ShouldNotBe(secondRow.TokenHash);
        firstRow.Id.ShouldNotBe(secondRow.Id);
    }
}
