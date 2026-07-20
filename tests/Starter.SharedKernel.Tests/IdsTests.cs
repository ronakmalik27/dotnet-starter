using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class IdsTests
{
    [Fact]
    public void NewId_NoArguments_MintsVersion7()
    {
        Ids.NewId().Version.ShouldBe(7);
    }

    [Fact]
    public void NewId_ExplicitTimestamp_MintsVersion7()
    {
        Ids.NewId(DateTimeOffset.UnixEpoch).Version.ShouldBe(7);
    }

    [Fact]
    public void NewId_TwoCalls_MintDistinctIds()
    {
        Ids.NewId().ShouldNotBe(Ids.NewId());
    }

    [Fact]
    public void NewId_ExplicitTimestamp_EmbedsUnixMilliseconds()
    {
        // RFC 9562 UUIDv7 layout: the first 48 bits are big-endian Unix
        // milliseconds, so the first 12 hex characters spell the timestamp.
        var timestamp = new DateTimeOffset(2026, 7, 7, 10, 30, 0, TimeSpan.Zero);

        var id = Ids.NewId(timestamp);

        var embeddedMs = Convert.ToInt64(id.ToString("N")[..12], 16);
        embeddedMs.ShouldBe(timestamp.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void NewId_IncreasingTimestamps_SortInMintOrder()
    {
        // The B-tree locality argument (doc 07) rests on ids ordering by
        // creation time; both string and Guid comparison must agree.
        var start = new DateTimeOffset(2026, 7, 7, 10, 30, 0, TimeSpan.Zero);
        var ids = Enumerable.Range(0, 100)
            .Select(i => Ids.NewId(start.AddMilliseconds(i)))
            .ToList();

        ids.Select(id => id.ToString()).ShouldBeInOrder();
        ids.ShouldBeInOrder();
    }

    [Fact]
    public void NewId_SameMillisecondBurst_SharesTimestampPrefixAndStaysUnique()
    {
        // .NET's CreateVersion7 fills rand_a/rand_b with random bits, not a
        // monotonic counter, so order WITHIN one millisecond is unspecified
        // and nothing in Starter may rely on it. What the doc 07 locality
        // argument needs from a same-instant burst is that all ids share
        // the 48-bit millisecond prefix (co-located B-tree pages) and stay
        // unique; that is what this asserts.
        var timestamp = new DateTimeOffset(2026, 7, 7, 10, 30, 0, TimeSpan.Zero);
        var ids = Enumerable.Range(0, 100).Select(_ => Ids.NewId(timestamp)).ToList();

        ids.Select(id => id.ToString("N")[..12]).Distinct().ShouldHaveSingleItem();
        ids.Distinct().Count().ShouldBe(ids.Count);
    }

    [Fact]
    public void NewId_TimestampBeforeUnixEpoch_Throws()
    {
        // UUIDv7 cannot encode pre-epoch instants; minting one is a bug.
        Should.Throw<ArgumentOutOfRangeException>(
            () => Ids.NewId(DateTimeOffset.UnixEpoch.AddMilliseconds(-1)));
    }
}
