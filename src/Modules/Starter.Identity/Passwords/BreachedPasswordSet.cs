using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Passwords;

/// <summary>
/// The FR-AUTH-01 offline breached-password check: registrations (and
/// later password sets) are rejected when the password appears in known
/// breach corpora. The set ships as an embedded resource - 250k truncated
/// SHA-1 prefixes built from two SecLists top-1M lists filtered to the
/// policy length floor (scripts/dev/build-breached-password-set.py
/// documents sources, license, and regeneration) - so the check is fully
/// offline: no password material ever leaves the process (doc 10 4.1),
/// which is the property the HIBP k-anonymity protocol approximates for
/// callers that cannot hold the set locally.
/// </summary>
internal sealed class BreachedPasswordSet
{
    private const string ResourceName = "Starter.Identity.Passwords.breached-passwords.bin";

    private const int PrefixBytes = 8;

    private readonly ulong[] _prefixes;

    public BreachedPasswordSet()
        : this(LoadEmbedded())
    {
    }

    internal BreachedPasswordSet(ulong[] sortedPrefixes)
    {
        ArgumentNullException.ThrowIfNull(sortedPrefixes);
        _prefixes = sortedPrefixes;
    }

    /// <summary>Entries loaded; a canary against a truncated resource.</summary>
    internal int Count => _prefixes.Length;

    public bool Contains(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        // SHA-1 as the corpus convention (HIBP's), not as a security
        // primitive: membership lookup only, preimage strength irrelevant,
        // hence the scoped CA5350 suppression.
#pragma warning disable CA5350
        var digest = SHA1.HashData(Encoding.UTF8.GetBytes(password));
#pragma warning restore CA5350
        var prefix = BinaryPrimitives.ReadUInt64BigEndian(digest);
        return Array.BinarySearch(_prefixes, prefix) >= 0;
    }

    private static ulong[] LoadEmbedded()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException(
                $"Embedded resource {ResourceName} is missing; regenerate it with scripts/dev/build-breached-password-set.py.");

        if (stream.Length == 0 || stream.Length % PrefixBytes != 0)
        {
            throw new InvalidOperationException(
                $"Embedded resource {ResourceName} is corrupt ({stream.Length} bytes); regenerate it.");
        }

        var buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);

        var prefixes = new ulong[buffer.Length / PrefixBytes];
        for (var i = 0; i < prefixes.Length; i++)
        {
            prefixes[i] = BinaryPrimitives.ReadUInt64BigEndian(
                buffer.AsSpan(i * PrefixBytes, PrefixBytes));
        }

        return prefixes;
    }
}
