using Shouldly;
using Starter.Platform.Data;
using Starter.SharedKernel;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The metered-quota period math as unit tests (quotas.md section 3), DB-free and
/// driven by a pinned Clock: the calendar-month window derives from
/// <see cref="Clock.UtcNow"/>, so a test can fix the instant and assert
/// <see cref="QuotaPeriod.PeriodStart"/> / <see cref="QuotaPeriod.ResetAt"/> at a
/// mid-month moment and across a December-to-January rollover, and that the
/// Retry-After clamp never goes negative.
/// </summary>
public class QuotaPeriodTests
{
    // A fixed-instant TimeProvider so the Clock is deterministic without pulling the
    // testing package in (Clock only reads GetUtcNow). Time flows through Clock, so
    // no banned DateTime.UtcNow appears here.
    private sealed class PinnedTimeProvider(DateTimeOffset instant) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => instant;
    }

    private static Clock At(DateTimeOffset instant) => new(new PinnedTimeProvider(instant));

    [Fact]
    public void PeriodStartAndReset_MidMonth_AnchorToFirstOfMonthAndFirstOfNextMonth()
    {
        var clock = At(new DateTimeOffset(2026, 7, 15, 13, 45, 30, TimeSpan.Zero));

        QuotaPeriod.PeriodStart(clock.UtcNow).ShouldBe(new DateOnly(2026, 7, 1));
        QuotaPeriod.ResetAt(clock.UtcNow)
            .ShouldBe(new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void PeriodStartAndReset_DecemberInstant_RollsIntoTheNextJanuary()
    {
        var clock = At(new DateTimeOffset(2026, 12, 20, 10, 0, 0, TimeSpan.Zero));

        QuotaPeriod.PeriodStart(clock.UtcNow).ShouldBe(new DateOnly(2026, 12, 1));
        // The reset crosses the year boundary: first of the next January.
        QuotaPeriod.ResetAt(clock.UtcNow)
            .ShouldBe(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void PeriodStart_NonUtcOffsetInstant_NormalizesToUtcBeforeAnchoring()
    {
        // 00:30 on Aug 1 at +05:30 is still 19:00 on Jul 31 UTC, so the period is July.
        var clock = At(new DateTimeOffset(2026, 8, 1, 0, 30, 0, TimeSpan.FromHours(5.5)));

        QuotaPeriod.PeriodStart(clock.UtcNow).ShouldBe(new DateOnly(2026, 7, 1));
        QuotaPeriod.ResetAt(clock.UtcNow)
            .ShouldBe(new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void RetryAfterSeconds_BeforeReset_IsThePositiveSecondsUntilReset()
    {
        var clock = At(new DateTimeOffset(2026, 7, 31, 23, 59, 0, TimeSpan.Zero));
        var resetAt = QuotaPeriod.ResetAt(clock.UtcNow); // 2026-08-01T00:00:00Z

        QuotaPeriod.RetryAfterSeconds(clock.UtcNow, resetAt).ShouldBe(60);
    }

    [Fact]
    public void RetryAfterSeconds_RoundsUpAPartialSecond()
    {
        var now = new DateTimeOffset(2026, 7, 15, 0, 0, 0, 500, TimeSpan.Zero);
        var resetAt = new DateTimeOffset(2026, 7, 15, 0, 0, 1, 0, TimeSpan.Zero);

        // 0.5s to the reset rounds up to 1 whole second.
        QuotaPeriod.RetryAfterSeconds(now, resetAt).ShouldBe(1);
    }

    [Fact]
    public void RetryAfterSeconds_AtOrPastReset_ClampsToZero_NeverNegative()
    {
        var resetAt = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

        // Exactly at the reset: 0.
        QuotaPeriod.RetryAfterSeconds(resetAt, resetAt).ShouldBe(0);
        // Past the reset: clamped to 0, never negative.
        QuotaPeriod.RetryAfterSeconds(resetAt.AddSeconds(90), resetAt).ShouldBe(0);
    }
}
