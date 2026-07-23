using Shouldly;
using Starter.Identity.Passwords;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// Password policy: minimum length (from the platform policy defaults, 10 by
/// default), offline breach check, and deliberately nothing else - no composition
/// rules.
/// </summary>
public class PasswordPolicyTests
{
    private static readonly PasswordPolicy Policy = new(new BreachedPasswordSet(), new StubPolicyDefaults());

    [Fact]
    public async Task Check_NineCharacters_TooShort()
    {
        var result = await Policy.CheckAsync("abcdefghi", CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_too_short");
    }

    [Fact]
    public async Task Check_TenStrongCharacters_Passes()
    {
        (await Policy.CheckAsync("kZ2!vq81#Ls0", CancellationToken.None)).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task Check_NoCompositionRules_AllLowercasePassphrasePasses()
    {
        (await Policy.CheckAsync("battery staple horse purple", CancellationToken.None))
            .IsSuccess.ShouldBeTrue();
    }

    [Theory]
    [InlineData("1234567890")]
    [InlineData("qwertyuiop")]
    [InlineData("password123")]
    public async Task Check_KnownBreachedPassword_Rejected(string breached)
    {
        var result = await Policy.CheckAsync(breached, CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_breached");
    }

    [Fact]
    public async Task Check_AbsurdLength_Rejected()
    {
        // Argon2 cost scales with input length; a megabyte password is a
        // CPU-exhaustion vector, not a credential.
        var result = await Policy.CheckAsync(new string('x', 300), CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error.Code.ShouldBe("auth.password_too_long");
    }

    [Fact]
    public async Task Check_MinimumLength_ComesFromPolicyDefaults()
    {
        // Raise the platform minimum to 12: an 11-char password now fails where the
        // built-in 10 would have passed it. This is the reader-driven minimum.
        var policy = new PasswordPolicy(
            new BreachedPasswordSet(),
            new StubPolicyDefaults(PolicyDefaults.BuiltIn with { PasswordMinLength = 12 }));

        var eleven = await policy.CheckAsync("kZ2!vq81#La", CancellationToken.None);
        eleven.IsFailure.ShouldBeTrue();
        eleven.Error.Code.ShouldBe("auth.password_too_short");

        (await policy.CheckAsync("kZ2!vq81#Ls0", CancellationToken.None)).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void BreachedSet_LoadsFullCorpus()
    {
        // A truncated embedded resource would silently weaken the policy;
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
