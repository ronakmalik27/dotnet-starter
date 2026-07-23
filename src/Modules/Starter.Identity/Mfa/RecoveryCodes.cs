using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Mfa;

/// <summary>
/// MFA recovery-code material (mfa-totp.md section 6): 10 codes, each 16
/// base32 characters (~80 bits), shown once and stored as a SHA-256 hex
/// digest. The 80-bit floor is deliberate - a recovery code is human-typed so
/// it cannot be 256-bit like the other hashed secrets in this codebase, but
/// ~80 bits keeps a leaked-table offline brute force infeasible while a ~50-bit
/// code would not. Codes are formatted in dash-separated groups for legibility;
/// the canonical hashed form strips the separators and upper-cases, so a code
/// typed with or without dashes verifies. A high-entropy hash lookup needs no
/// constant-time compare (the API-key-resolver precedent).
/// </summary>
internal static class RecoveryCodes
{
    /// <summary>How many codes a generation produces.</summary>
    public const int Count = 10;

    // 10 random bytes = 80 bits = exactly 16 base32 characters (no padding).
    private const int CodeBytes = 10;

    private const int GroupSize = 4;

    /// <summary>
    /// Generates a fresh set. Each returned tuple carries the display form
    /// (dash-grouped, shown to the user once) and the SHA-256 hex of the
    /// canonical form (stored).
    /// </summary>
    public static IReadOnlyList<(string Display, string Hash)> Generate()
    {
        var codes = new List<(string, string)>(Count);
        for (var index = 0; index < Count; index++)
        {
            var canonical = Base32.Encode(RandomNumberGenerator.GetBytes(CodeBytes));
            codes.Add((Group(canonical), Hash(canonical)));
        }

        return codes;
    }

    /// <summary>
    /// Normalizes a submitted code to the canonical hashed form: drop every
    /// non-base32 character (dashes, spaces) and upper-case, so the same code
    /// verifies whether typed grouped or bare, upper or lower.
    /// </summary>
    public static string Normalize(string submitted)
    {
        ArgumentNullException.ThrowIfNull(submitted);
        var builder = new StringBuilder(submitted.Length);
        foreach (var character in submitted)
        {
            var upper = char.ToUpperInvariant(character);
            if ((upper >= 'A' && upper <= 'Z') || (upper >= '2' && upper <= '7'))
            {
                builder.Append(upper);
            }
        }

        return builder.ToString();
    }

    /// <summary>SHA-256 hex of a canonical (normalized) recovery code.</summary>
    public static string Hash(string canonicalCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(canonicalCode);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCode)));
    }

    private static string Group(string canonical)
    {
        var builder = new StringBuilder(canonical.Length + (canonical.Length / GroupSize));
        for (var index = 0; index < canonical.Length; index++)
        {
            if (index > 0 && index % GroupSize == 0)
            {
                builder.Append('-');
            }

            builder.Append(canonical[index]);
        }

        return builder.ToString();
    }
}
