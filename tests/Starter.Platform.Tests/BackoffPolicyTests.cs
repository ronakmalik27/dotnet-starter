using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The lease arithmetic as pure math: no clock, no database, every branch
/// of send_timeout + min(2^attempts, cap) + jitter.
/// </summary>
public class BackoffPolicyTests
{
    private static readonly OutboxOptions Options = new();

    [Fact]
    public void Lease_FirstAttemptFastLane_IsSendTimeoutPlusOneSecond()
    {
        var lease = BackoffPolicy.Lease(Options, Lane.Fast, attemptsBeforeClaim: 0, jitterSample: 0);

        lease.ShouldBe(Options.FastSendTimeout + TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Lease_SlowLane_UsesSlowSendTimeout()
    {
        var lease = BackoffPolicy.Lease(Options, Lane.Slow, attemptsBeforeClaim: 0, jitterSample: 0);

        lease.ShouldBe(Options.SlowSendTimeout + TimeSpan.FromSeconds(1));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(3, 8)]
    [InlineData(8, 256)]
    public void Lease_GrowingAttempts_DoublesBackoff(int attempts, int expectedBackoffSeconds)
    {
        var lease = BackoffPolicy.Lease(Options, Lane.Fast, attempts, jitterSample: 0);

        lease.ShouldBe(Options.FastSendTimeout + TimeSpan.FromSeconds(expectedBackoffSeconds));
    }

    [Fact]
    public void Lease_ManyAttempts_CapsAtMaxBackoff()
    {
        // 2^30 seconds is ~34 years; the policy caps the term at 300 s.
        var lease = BackoffPolicy.Lease(Options, Lane.Fast, attemptsBeforeClaim: 30, jitterSample: 0);

        lease.ShouldBe(Options.FastSendTimeout + Options.MaxBackoff);
    }

    [Fact]
    public void Lease_JitterSample_AddsAtMostMaxJitter()
    {
        var floor = BackoffPolicy.Lease(Options, Lane.Fast, 0, jitterSample: 0);
        var nearCeiling = BackoffPolicy.Lease(Options, Lane.Fast, 0, jitterSample: 0.999);

        (nearCeiling - floor).ShouldBeLessThan(Options.MaxJitter);
        nearCeiling.ShouldBeGreaterThan(floor);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.0)]
    public void Lease_JitterSampleOutOfRange_Throws(double sample)
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => BackoffPolicy.Lease(Options, Lane.Fast, 0, sample));
    }

    [Fact]
    public void Lease_NegativeAttempts_Throws()
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => BackoffPolicy.Lease(Options, Lane.Fast, -1, 0));
    }
}
