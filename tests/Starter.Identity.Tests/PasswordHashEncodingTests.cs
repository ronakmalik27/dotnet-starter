using Shouldly;
using Starter.Identity.Passwords;
using Xunit;

namespace Starter.Identity.Tests;

public class PasswordHashEncodingTests
{
    [Fact]
    public void FormatThenParse_RoundTrips()
    {
        var parameters = new Argon2Parameters(19456, 2, 1);
        var salt = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var hash = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();

        var encoded = PasswordHashEncoding.Format(parameters, salt, hash);
        PasswordHashEncoding.TryParse(encoded, out var parsed, out var parsedSalt, out var parsedHash)
            .ShouldBeTrue();

        parsed.ShouldBe(parameters);
        parsedSalt.ShouldBe(salt);
        parsedHash.ShouldBe(hash);
    }

    [Theory]
    [InlineData("")]
    [InlineData("plainly not a hash")]
    [InlineData("$argon2i$v=19$m=19456,t=2,p=1$AAAA$BBBB")] // wrong variant
    [InlineData("$argon2id$v=19$m=19456,t=2$AAAA$BBBB")] // missing p
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$AAAA")] // missing hash
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$!!$BBBB")] // bad base64
    [InlineData("$argon2id$v=19$m=0,t=2,p=1$AAAA$BBBB")] // non-positive cost
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1,x=9$AAAA$BBBB")] // unknown key
    public void TryParse_Malformed_False(string encoded)
    {
        PasswordHashEncoding.TryParse(encoded, out _, out _, out _).ShouldBeFalse();
    }
}
