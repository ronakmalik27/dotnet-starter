using System.Text;
using Shouldly;
using Starter.Identity.Mfa;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// RFC 6238 TOTP correctness (mfa-totp.md section 3), the load-bearing
/// algorithm gate. RFC 6238 Appendix B publishes its vectors as 8-DIGIT codes;
/// this feature uses 6 digits, and the correct 6-digit value is the LAST six of
/// the 8-digit value (<c>fullCode mod 1_000_000</c>), NOT the first six - real
/// authenticators truncate to the low-order digits. The adapted 6-digit values
/// for the SHA-1 vectors are asserted directly, so a byte-order or truncation
/// bug fails the build. Also proves the +/-1 skew window and the replay guard.
/// </summary>
public class TotpTests
{
    // The RFC 6238 SHA-1 seed: ASCII "12345678901234567890" (20 bytes).
    private static readonly byte[] Seed = Encoding.ASCII.GetBytes("12345678901234567890");

    public static TheoryData<long, string> Rfc6238Sha1Vectors => new()
    {
        // T -> the low six digits of the published 8-digit SHA-1 code.
        //  59        -> 94287082 -> 287082
        //  1111111109 -> 07081804 -> 081804
        //  1111111111 -> 14050471 -> 050471
        { 59L, "287082" },
        { 1111111109L, "081804" },
        { 1111111111L, "050471" },
    };

    [Theory]
    [MemberData(nameof(Rfc6238Sha1Vectors))]
    public void Generate_MatchesAdaptedRfc6238Sha1Vectors(long unixSeconds, string expected)
    {
        var step = unixSeconds / Totp.StepSeconds;

        Totp.Generate(Seed, step).ShouldBe(expected);
    }

    [Fact]
    public void Generate_IsAlwaysSixDigits()
    {
        // A truncation whose low six digits start with zeros must still render
        // as six characters (the T=1111111109 vector already exercises this:
        // "081804"). Spot-check a range of steps for the six-digit invariant.
        for (long step = 0; step < 200; step++)
        {
            var code = Totp.Generate(Seed, step);
            code.Length.ShouldBe(6);
            code.ShouldAllBe(character => char.IsAsciiDigit(character));
        }
    }

    [Fact]
    public void Verify_AcceptsTheCurrentStep_AndTheAdjacentSteps()
    {
        const long currentStep = 55_000_000L;
        var code = Totp.Generate(Seed, currentStep);

        // The code for the current step verifies at the current step.
        Totp.Verify(Seed, code, currentStep, lastAcceptedStep: null, out var matched).ShouldBeTrue();
        matched.ShouldBe(currentStep);

        // A code minted one step earlier still verifies while the clock is at
        // the current step (the +/-1 skew window covers a ~30s client drift).
        var previousCode = Totp.Generate(Seed, currentStep - 1);
        Totp.Verify(Seed, previousCode, currentStep, lastAcceptedStep: null, out var previousMatched).ShouldBeTrue();
        previousMatched.ShouldBe(currentStep - 1);
    }

    [Fact]
    public void Verify_RejectsACodeTwoStepsAway()
    {
        const long currentStep = 55_000_000L;
        var twoStepsAway = Totp.Generate(Seed, currentStep + 2);

        // Outside the +/-1 window: rejected.
        Totp.Verify(Seed, twoStepsAway, currentStep, lastAcceptedStep: null, out _).ShouldBeFalse();
    }

    [Fact]
    public void Verify_ReplayGuard_RejectsAStepAtOrBelowTheLastAcceptedStep()
    {
        const long currentStep = 55_000_000L;
        var code = Totp.Generate(Seed, currentStep);

        // Once the current step has been accepted, the same code (same step)
        // is a replay: step <= last_step is rejected.
        Totp.Verify(Seed, code, currentStep, lastAcceptedStep: currentStep, out _).ShouldBeFalse();

        // The neighbouring earlier step is also at-or-below the guard: rejected.
        var previousCode = Totp.Generate(Seed, currentStep - 1);
        Totp.Verify(Seed, previousCode, currentStep, lastAcceptedStep: currentStep, out _).ShouldBeFalse();

        // The next step is above the guard and still verifies (genuine next
        // login), so the guard never wrongly rejects a legitimate advance.
        var nextCode = Totp.Generate(Seed, currentStep + 1);
        Totp.Verify(Seed, nextCode, currentStep, lastAcceptedStep: currentStep, out var matched).ShouldBeTrue();
        matched.ShouldBe(currentStep + 1);
    }

    [Fact]
    public void Verify_RejectsANonSixDigitOrEmptyCode()
    {
        const long currentStep = 55_000_000L;

        Totp.Verify(Seed, string.Empty, currentStep, lastAcceptedStep: null, out _).ShouldBeFalse();
        // A recovery-code-shaped string never matches a TOTP comparison.
        Totp.Verify(Seed, "MZXW6YTBOI", currentStep, lastAcceptedStep: null, out _).ShouldBeFalse();
    }
}
