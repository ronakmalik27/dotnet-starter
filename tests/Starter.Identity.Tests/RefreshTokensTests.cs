using Shouldly;
using Starter.Identity.Tokens;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>Refresh-token material: 256-bit random, stored hashed.</summary>
public class RefreshTokensTests
{
    [Fact]
    public void NewToken_IsBase64UrlOf32Bytes()
    {
        var token = RefreshTokens.NewToken();

        token.Length.ShouldBe(43); // ceil(32 * 8 / 6), unpadded
        token.ShouldAllBe(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');
    }

    [Fact]
    public void NewToken_NeverRepeats()
    {
        var tokens = Enumerable.Range(0, 1000).Select(_ => RefreshTokens.NewToken()).ToHashSet(StringComparer.Ordinal);

        tokens.Count.ShouldBe(1000);
    }

    [Fact]
    public void Hash_IsDeterministicLowercaseHexSha256()
    {
        var token = RefreshTokens.NewToken();

        var hash = RefreshTokens.Hash(token);

        hash.ShouldBe(RefreshTokens.Hash(token));
        hash.Length.ShouldBe(64);
        hash.ShouldAllBe(c => char.IsAsciiDigit(c) || (c >= 'a' && c <= 'f'));
    }

    [Fact]
    public void Hash_DiffersPerToken()
    {
        RefreshTokens.Hash(RefreshTokens.NewToken())
            .ShouldNotBe(RefreshTokens.Hash(RefreshTokens.NewToken()));
    }
}
