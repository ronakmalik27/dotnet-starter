using Microsoft.Extensions.Time.Testing;
using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class ClockTests
{
    [Fact]
    public void Ctor_NullTimeProvider_ThrowsArgumentNull()
    {
        Should.Throw<ArgumentNullException>(() => new Clock(null!));
    }

    [Fact]
    public void UtcNow_FakeTimeProvider_ReturnsExactSeededInstant()
    {
        var seeded = new DateTimeOffset(2026, 7, 7, 10, 0, 0, TimeSpan.Zero);
        var clock = new Clock(new FakeTimeProvider(seeded));

        clock.UtcNow.ShouldBe(seeded);
    }

    [Fact]
    public void UtcNow_FakeTimeProviderAdvanced_ReflectsAdvance()
    {
        var seeded = new DateTimeOffset(2026, 7, 7, 10, 0, 0, TimeSpan.Zero);
        var fake = new FakeTimeProvider(seeded);
        var clock = new Clock(fake);

        fake.Advance(TimeSpan.FromMinutes(5));

        clock.UtcNow.ShouldBe(seeded.AddMinutes(5));
    }

    [Fact]
    public void UtcNow_FakeSeededWithIstOffset_NormalizesToUtc()
    {
        // Storage time is UTC. A positive-offset instant comes back as
        // the same instant with a zero offset.
        var istInstant = new DateTimeOffset(2026, 7, 8, 2, 0, 0, TimeSpan.FromHours(5.5));
        var clock = new Clock(new FakeTimeProvider(istInstant));

        clock.UtcNow.Offset.ShouldBe(TimeSpan.Zero);
        clock.UtcNow.ShouldBe(istInstant);
    }

    [Fact]
    public void TodayUtc_LateEveningUtc_ReturnsUtcDateNotLocalDate()
    {
        // 23:59 UTC on the 7th is already the 8th in a positive-offset zone;
        // TodayUtc must say the 7th regardless of any local zone.
        var lateUtc = new DateTimeOffset(2026, 7, 7, 23, 59, 59, TimeSpan.Zero);
        var clock = new Clock(new FakeTimeProvider(lateUtc));

        clock.TodayUtc.ShouldBe(new DateOnly(2026, 7, 7));
    }

    [Fact]
    public void System_UtcNow_HasZeroOffset()
    {
        // Structural assertion only (no time value): the system-backed
        // clock always reports instants in UTC.
        Clock.System.UtcNow.Offset.ShouldBe(TimeSpan.Zero);
    }
}
