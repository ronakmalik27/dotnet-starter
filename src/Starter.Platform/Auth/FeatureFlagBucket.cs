using System.Text;

namespace Starter.Platform.Auth;

/// <summary>
/// The deterministic percentage-rollout bucket (feature-flags.md sections 1, 3): a
/// stable hash of <c>(flagKey, tenantId)</c> in <c>[0, 99]</c>, compared to a flag's
/// rollout percent. A flag at N% is ON for a tenant when <c>Bucket &lt; N</c>, so the
/// same tenant is stably in or out across every replica, restart, and request, and
/// raising the percent only ever ADDS tenants (never flips an in-tenant out).
/// <para>
/// The hash is FNV-1a computed HERE, in application code, over the UTF-8 bytes of
/// <c>flagKey + ":" + tenantId</c>, accumulated as an UNSIGNED 32-bit integer, then
/// <c>% 100</c> - unsigned throughout, so there is no <c>Math.Abs</c> (and no
/// <c>Math.Abs(int.MinValue)</c> overflow, which throws). It must NEVER use
/// <c>string.GetHashCode()</c> or <c>HashCode.Combine</c>: both are randomized per
/// process by .NET (a hash-flooding mitigation), so they would give a different
/// bucket on every replica and restart - the same tenant would flicker in and out of
/// a rollout, and a same-process unit test could not catch it (the seed is stable
/// within one process). A golden-value unit test pins one input to a hardcoded
/// literal, so a <c>GetHashCode</c>-based implementation fails immediately.
/// </para>
/// </summary>
public static class FeatureFlagBucket
{
    private const uint FnvOffsetBasis = 2166136261;
    private const uint FnvPrime = 16777619;

    /// <summary>
    /// The rollout bucket in <c>[0, 99]</c> for <paramref name="flagKey"/> and
    /// <paramref name="tenantId"/>. Deterministic and cross-process-stable.
    /// </summary>
    public static int Bucket(string flagKey, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(flagKey);

        // The exact hashed string is flagKey + ":" + the tenant's canonical
        // (lowercase, hyphenated "D") guid text; the golden-value test pins it.
        var bytes = Encoding.UTF8.GetBytes($"{flagKey}:{tenantId}");

        var hash = FnvOffsetBasis;
        foreach (var b in bytes)
        {
            hash ^= b;
            hash *= FnvPrime;
        }

        // Unsigned modulo: no Math.Abs, no signed-overflow edge case.
        return (int)(hash % 100u);
    }
}
