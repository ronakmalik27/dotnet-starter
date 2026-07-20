using Shouldly;
using Starter.Identity.Passwords;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// FR-AUTH-01: length >= 10, offline breach check, and deliberately
/// nothing else - no composition rules.
/// </summary>
public class PasswordPolicyTests
{
    private static readonly PasswordPolicy Policy = new(new BreachedPasswordSet());

    [Fact]
    public void Check_NineCharacters_TooShort()
    {
        var result = Policy.Check("abcdefghi");

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_too_short");
    }

    [Fact]
    public void Check_TenStrongCharacters_Passes()
    {
        Policy.Check("kZ2!vq81#Ls0").IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Check_NoCompositionRules_AllLowercasePassphrasePasses()
    {
        Policy.Check("battery staple horse purple").IsSuccess.ShouldBeTrue();
    }

    [Theory]
    [InlineData("1234567890")]
    [InlineData("qwertyuiop")]
    [InlineData("password123")]
    public void Check_KnownBreachedPassword_Rejected(string breached)
    {
        var result = Policy.Check(breached);

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_breached");
    }

    [Fact]
    public void Check_AbsurdLength_Rejected()
    {
        // Argon2 cost scales with input length; a megabyte password is a
        // CPU-exhaustion vector, not a credential.
        var result = Policy.Check(new string('x', 300));

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_too_long");
    }

    [Fact]
    public void BreachedSet_LoadsFullCorpus()
    {
        // A truncated embedded resource would silently weaken FR-AUTH-01;
        // the two SecLists top-1M sources filtered to >= 10 chars land
        // around a quarter million entries.
        new BreachedPasswordSet().Count.ShouldBeGreaterThan(200_000);
    }

    [Fact]
    public void BreachedSet_DoesNotContainARandomStrongPassword()
    {
        var random = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

        new BreachedPasswordSet().Contains(random).ShouldBeFalse();
    }
}
