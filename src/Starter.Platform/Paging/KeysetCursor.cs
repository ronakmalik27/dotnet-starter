using System.Buffers.Binary;
using System.Buffers.Text;

namespace Starter.Platform.Paging;

/// <summary>
/// The opaque cursor for the <c>(CreatedAt desc, Id desc)</c> keyset sort key:
/// the sort key of the last row on a page, encoded to a URL-safe base64 string
/// the client echoes back on the next request. This is the pagination
/// convention modules copy - the sort key is <c>(DateTimeOffset CreatedAt,
/// Guid Id)</c>, the instant plus a UUIDv7 tiebreaker, which is unique and
/// stable per row.
///
/// The cursor is a position, not a token of trust: it encodes only the public
/// sort key, so tampering can at worst return a differently-positioned page,
/// never another owner's rows (the owner filter is applied independently by
/// the query). Malformed input decodes to a failure the caller maps to a 400
/// / 422 validation problem, never a 500.
///
/// Wire format: 8 bytes of UTC ticks (little-endian) followed by the 16-byte
/// Guid, base64url-encoded. CreatedAt is normalized to UTC on decode, matching
/// how a Postgres <c>timestamp with time zone</c> column compares by instant.
/// </summary>
public readonly record struct KeysetCursor(DateTimeOffset CreatedAt, Guid Id)
{
    private const int PayloadLength = sizeof(long) + 16;

    /// <summary>Encodes this sort key to its opaque URL-safe cursor string.</summary>
    public string Encode()
    {
        Span<byte> payload = stackalloc byte[PayloadLength];
        BinaryPrimitives.WriteInt64LittleEndian(payload, CreatedAt.UtcTicks);
        Id.TryWriteBytes(payload[sizeof(long)..]);
        return Base64Url.EncodeToString(payload);
    }

    /// <summary>
    /// Decodes a cursor produced by <see cref="Encode"/>. Returns false for
    /// null, empty, non-base64url, wrong-length, or out-of-range input, so a
    /// tampered or stale cursor is a clean client error rather than a throw.
    /// </summary>
    public static bool TryDecode(string? value, out KeysetCursor cursor)
    {
        cursor = default;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        // Validate the shape first: IsValid never throws, whereas the Try*
        // decoders throw FormatException on an illegal character. Reject
        // anything that is not exactly our payload length while we are here.
        if (!Base64Url.IsValid(value, out var decodedLength) || decodedLength != PayloadLength)
        {
            return false;
        }

        Span<byte> payload = stackalloc byte[PayloadLength];
        Base64Url.DecodeFromChars(value, payload);

        var ticks = BinaryPrimitives.ReadInt64LittleEndian(payload);
        if (ticks < 0 || ticks > DateTimeOffset.MaxValue.UtcTicks)
        {
            return false;
        }

        var id = new Guid(payload[sizeof(long)..]);
        cursor = new KeysetCursor(new DateTimeOffset(ticks, TimeSpan.Zero), id);
        return true;
    }
}
