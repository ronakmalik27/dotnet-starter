using Shouldly;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The deterministic rollout bucket (feature-flags.md sections 1, 3). The
/// GOLDEN-VALUE test is the load-bearing one: it pins <c>Bucket("known-flag",
/// knownGuid)</c> to a hardcoded literal computed from the fixed FNV-1a algorithm
/// over the UTF-8 bytes of <c>flagKey + ":" + tenantId</c>. A <c>string.GetHashCode()</c>
/// / <c>HashCode.Combine</c> implementation (randomized per process by .NET) would
/// produce a different, process-dependent number and fail this on the FIRST run in
/// ANY process - which a same-process repeat-call test could never catch.
/// </summary>
public class FeatureFlagBucketTests
{
    // knownFlag + ":" + knownGuid = "known-flag:11111111-2222-3333-4444-555555555555".
    // FNV-1a (32-bit, offset 2166136261, prime 16777619) over its UTF-8 bytes is
    // 585028025; 585028025 % 100 = 25. Recompute this literal only if the algorithm
    // deliberately changes (which re-buckets every tenant - a breaking rollout change).
    private const string KnownFlag = "known-flag";
    private const int GoldenBucket = 25;

    private static readonly Guid KnownTenant = Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Fact]
    public void Bucket_KnownInput_MatchesTheGoldenLiteral()
    {
        FeatureFlagBucket.Bucket(KnownFlag, KnownTenant).ShouldBe(GoldenBucket);
    }

    [Fact]
    public void Bucket_IsDeterministic_AcrossRepeatedCalls()
    {
        // Stable within a process is necessary but NOT sufficient (GetHashCode is
        // also stable within a process); the golden test above is what catches the
        // per-process-seed bug. This pins the "same value every call" contract.
        var first = FeatureFlagBucket.Bucket(KnownFlag, KnownTenant);
        for (var i = 0; i < 1000; i++)
        {
            FeatureFlagBucket.Bucket(KnownFlag, KnownTenant).ShouldBe(first);
        }
    }

    [Fact]
    public void Bucket_IsAlwaysInRange_ZeroToNinetyNine()
    {
        for (var i = 0; i < 5000; i++)
        {
            var bucket = FeatureFlagBucket.Bucket($"flag-{i}", Guid.NewGuid());
            bucket.ShouldBeInRange(0, 99);
        }
    }

    [Fact]
    public void Bucket_MonotonicRollout_NeverFlipsAnInTenantOut()
    {
        // The whole point of a stable bucket: ON iff bucket < percent, so raising the
        // percent can only ever admit more tenants, never evict one already in.
        var tenant = Guid.NewGuid();
        var bucket = FeatureFlagBucket.Bucket(KnownFlag, tenant);

        for (var percent = 0; percent <= 100; percent++)
        {
            var isIn = bucket < percent;
            if (isIn)
            {
                // Once in at some percent, in at every higher percent.
                for (var higher = percent; higher <= 100; higher++)
                {
                    (bucket < higher).ShouldBeTrue();
                }

                break;
            }
        }
    }
}
