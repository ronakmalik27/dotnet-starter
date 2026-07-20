using Shouldly;
using Starter.Identity.Tokens;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>Doc 10 4.4 one-time-token material: 256-bit random, stored hashed.</summary>
public class OneTimeTokenSecretsTests
{
    [Fact]
    public void NewToken_IsBase64UrlOf32Bytes()
    {
        var token = OneTimeTokenSecrets.NewToken();

        token.Length.ShouldBe(43); // ceil(32 * 8 / 6), unpadded
        token.ShouldAllBe(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');
    }

    [Fact]
    public void NewToken_NeverRepeats()
    {
        var tokens = Enumerable.Range(0, 1000)
            .Select(_ => OneTimeTokenSecrets.NewToken())
            .ToHashSet(StringComparer.Ordinal);

        tokens.Count.ShouldBe(1000);
    }

    [Fact]
    public void Hash_IsDeterministicLowercaseHexSha256()
    {
        var token = OneTimeTokenSecrets.NewToken();

        var hash = OneTimeTokenSecrets.Hash(token);

        hash.ShouldBe(OneTimeTokenSecrets.Hash(token));
        hash.Length.ShouldBe(64);
        hash.ShouldAllBe(c => char.IsAsciiDigit(c) || (c >= 'a' && c <= 'f'));
    }

    [Fact]
    public void Hash_DiffersPerToken()
    {
        OneTimeTokenSecrets.Hash(OneTimeTokenSecrets.NewToken())
            .ShouldNotBe(OneTimeTokenSecrets.Hash(OneTimeTokenSecrets.NewToken()));
    }
}
