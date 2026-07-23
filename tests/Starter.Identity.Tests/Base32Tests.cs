using System.Text;
using Shouldly;
using Starter.Identity.Mfa;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// The hand-rolled RFC 4648 base32 codec, PINNED on the RFC 4648 section 10
/// test vectors (mfa-totp.md section 3). A wrong bit-packing or padding edge
/// case fails here rather than hiding behind the single clean-multiple-of-5
/// secret length. These vectors are the load-bearing correctness gate for the
/// codec, so they are asserted directly.
/// </summary>
public class Base32Tests
{
    // RFC 4648 section 10: the published ASCII -> base32 pairs, with padding.
    public static TheoryData<string, string> Rfc4648Vectors => new()
    {
        { string.Empty, string.Empty },
        { "f", "MY======" },
        { "fo", "MZXQ====" },
        { "foo", "MZXW6===" },
        { "foob", "MZXW6YQ=" },
        { "fooba", "MZXW6YTB" },
        { "foobar", "MZXW6YTBOI======" },
    };

    [Theory]
    [MemberData(nameof(Rfc4648Vectors))]
    public void Encode_MatchesRfc4648Vectors(string ascii, string expected)
    {
        Base32.Encode(Encoding.ASCII.GetBytes(ascii)).ShouldBe(expected);
    }

    [Theory]
    [MemberData(nameof(Rfc4648Vectors))]
    public void Decode_ReversesRfc4648Vectors(string ascii, string encoded)
    {
        Base32.Decode(encoded).ShouldBe(Encoding.ASCII.GetBytes(ascii));
    }

    [Fact]
    public void Decode_IsCaseInsensitive_AndIgnoresPadding()
    {
        // The lower-case, padded form decodes to the same bytes as the
        // canonical upper-case form.
        Base32.Decode("mzxw6ytb").ShouldBe(Encoding.ASCII.GetBytes("fooba"));
    }

    [Fact]
    public void EncodeDecode_RoundTrips_A20ByteSecret_WithNoPadding()
    {
        // The TOTP secret length: 20 bytes is a clean multiple of 5, so the
        // canonical form is exactly 32 characters with no '=' padding.
        var secret = new byte[20];
        for (var index = 0; index < secret.Length; index++)
        {
            secret[index] = (byte)(index * 7);
        }

        var encoded = Base32.Encode(secret);
        encoded.Length.ShouldBe(32);
        encoded.ShouldNotContain("=");
        Base32.Decode(encoded).ShouldBe(secret);
    }
}
