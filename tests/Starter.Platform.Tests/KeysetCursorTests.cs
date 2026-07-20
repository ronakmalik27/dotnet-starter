using Shouldly;
using Starter.Platform.Paging;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The keyset cursor codec: round-trips the (CreatedAt, Id) sort key through
/// its opaque URL-safe string, and rejects malformed input cleanly (a decode
/// failure, never a throw) so the endpoint answers a 4xx rather than a 500.
/// </summary>
public class KeysetCursorTests
{
    [Fact]
    public void EncodeThenDecode_RoundTripsTheSortKey()
    {
        var original = new KeysetCursor(
            new DateTimeOffset(2026, 7, 20, 12, 34, 56, 789, TimeSpan.Zero), Guid.NewGuid());

        var encoded = original.Encode();
        var ok = KeysetCursor.TryDecode(encoded, out var decoded);

        ok.ShouldBeTrue();
        decoded.ShouldBe(original);
        decoded.CreatedAt.UtcTicks.ShouldBe(original.CreatedAt.UtcTicks);
        decoded.Id.ShouldBe(original.Id);
    }

    [Fact]
    public void Encode_ProducesAUrlSafeStringWithNoPadding()
    {
        var encoded = new KeysetCursor(DateTimeOffset.UnixEpoch, Guid.NewGuid()).Encode();

        // base64url: '-'/'_' rather than '+'/'/', and no '=' padding, so the
        // cursor rides a query string without escaping.
        encoded.ShouldNotContain("+");
        encoded.ShouldNotContain("/");
        encoded.ShouldNotContain("=");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a cursor!!!")] // invalid base64url characters
    [InlineData("YWJj")]            // valid base64url, wrong length (3 bytes, not 24)
    public void TryDecode_MalformedInput_FailsCleanly(string? malformed)
    {
        var ok = KeysetCursor.TryDecode(malformed, out var decoded);

        ok.ShouldBeFalse();
        decoded.ShouldBe(default(KeysetCursor));
    }
}

/// <summary>
/// The shared page-size contract: an unspecified limit falls back to the
/// default; a specified one is clamped into [Min, Max] so no page is unbounded
/// and none runs with a zero or negative take.
/// </summary>
public class PageLimitTests
{
    [Fact]
    public void Clamp_Null_IsTheDefault() =>
        PageLimit.Clamp(null).ShouldBe(PageLimit.Default);

    [Theory]
    [InlineData(0, PageLimit.Min)]
    [InlineData(-5, PageLimit.Min)]
    [InlineData(1, 1)]
    [InlineData(20, 20)]
    [InlineData(100, 100)]
    [InlineData(1000, PageLimit.Max)]
    public void Clamp_SpecifiedValue_IsBoundedToTheRange(int requested, int expected) =>
        PageLimit.Clamp(requested).ShouldBe(expected);
}
