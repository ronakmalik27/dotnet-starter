using System.Text;

namespace Starter.Identity.Mfa;

/// <summary>
/// A hand-rolled RFC 4648 base32 codec (mfa-totp.md section 3). No base32
/// helper exists in the BCL or the repo, so one is written and PINNED against
/// the RFC 4648 section 10 test vectors (Base32Tests) - a wrong bit-packing or
/// padding edge case fails the build rather than hiding behind the single
/// 20-byte (clean multiple of 5) secret length that would mask it. Base32 is
/// the single canonical string form of the TOTP secret: the otpauth URI
/// carries it, the DataProtection protector stores <c>Protect(base32)</c>, and
/// TOTP computation base32-DECODES it back to the raw bytes for the HMAC.
/// </summary>
internal static class Base32
{
    // The RFC 4648 "standard" alphabet (upper-case A-Z then 2-7).
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private const char Padding = '=';

    /// <summary>
    /// Encodes bytes to a padded RFC 4648 base32 string. The output length is
    /// always a multiple of 8; trailing <c>=</c> pad the final group. A whole
    /// multiple of 5 input bytes (the 20-byte secret, the 10-byte recovery
    /// code) yields no padding.
    /// </summary>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder((data.Length + 4) / 5 * 8);
        var buffer = 0;
        var bitsInBuffer = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5)
            {
                bitsInBuffer -= 5;
                builder.Append(Alphabet[(buffer >> bitsInBuffer) & 0x1f]);
            }
        }

        // Flush the remaining <5 bits, left-aligned into a final symbol.
        if (bitsInBuffer > 0)
        {
            builder.Append(Alphabet[(buffer << (5 - bitsInBuffer)) & 0x1f]);
        }

        // Pad to the 8-symbol group boundary the RFC mandates.
        while (builder.Length % 8 != 0)
        {
            builder.Append(Padding);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Decodes an RFC 4648 base32 string back to bytes. Case-insensitive;
    /// padding and interior whitespace are ignored. Throws
    /// <see cref="FormatException"/> on a non-alphabet character - decoding is
    /// only ever fed a value this codec produced.
    /// </summary>
    public static byte[] Decode(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        var bytes = new List<byte>(encoded.Length * 5 / 8);
        var buffer = 0;
        var bitsInBuffer = 0;
        foreach (var symbol in encoded)
        {
            if (symbol == Padding || char.IsWhiteSpace(symbol))
            {
                continue;
            }

            var value = Alphabet.IndexOf(char.ToUpperInvariant(symbol), StringComparison.Ordinal);
            if (value < 0)
            {
                throw new FormatException($"'{symbol}' is not a base32 character.");
            }

            buffer = (buffer << 5) | value;
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                bytes.Add((byte)((buffer >> bitsInBuffer) & 0xff));
            }
        }

        return [.. bytes];
    }
}
