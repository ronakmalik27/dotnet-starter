using Shouldly;
using Starter.Identity.Passwords;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// Doc 10 4.1: Argon2id at the OWASP baseline (m=19456 KiB, t=2, p=1),
/// PHC-encoded with per-hash parameters, rehash detection when parameters
/// move.
/// </summary>
public class PasswordHasherTests
{
    [Fact]
    public void Hash_ProducesPhcString_WithCurrentDocumentedParameters()
    {
        var encoded = PasswordHasher.Hash("correct horse battery staple");

        encoded.ShouldStartWith("$argon2id$v=19$m=19456,t=2,p=1$");
    }

    [Fact]
    public void Verify_RightPassword_True()
    {
        var encoded = PasswordHasher.Hash("correct horse battery staple");

        PasswordHasher.Verify("correct horse battery staple", encoded).ShouldBeTrue();
    }

    [Fact]
    public void Verify_WrongPassword_False()
    {
        var encoded = PasswordHasher.Hash("correct horse battery staple");

        PasswordHasher.Verify("incorrect horse battery staple", encoded).ShouldBeFalse();
    }

    [Fact]
    public void Hash_SamePasswordTwice_DiffersByRandomSalt()
    {
        var password = "correct horse battery staple";

        PasswordHasher.Hash(password).ShouldNotBe(PasswordHasher.Hash(password));
    }

    [Fact]
    public void Verify_GarbageStoredHash_FalseNotThrow()
    {
        // A corrupt row must read as a failed login, never a 500.
        PasswordHasher.Verify("anything at all", "not-a-phc-string").ShouldBeFalse();
    }

    [Fact]
    public void NeedsRehash_CurrentParameters_False()
    {
        var encoded = PasswordHasher.Hash("correct horse battery staple");

        PasswordHasher.NeedsRehash(encoded).ShouldBeFalse();
    }

    [Fact]
    public void NeedsRehash_OlderParameters_True()
    {
        // A hash minted under weaker (pre-upgrade) parameters: same shape,
        // different costs - the rehash-on-login trigger (doc 10 4.1).
        var stale = "$argon2id$v=19$m=4096,t=1,p=1$"
            + Convert.ToBase64String(new byte[16]).TrimEnd('=')
            + "$"
            + Convert.ToBase64String(new byte[32]).TrimEnd('=');

        PasswordHasher.NeedsRehash(stale).ShouldBeTrue();
    }

    [Fact]
    public void NeedsRehash_Unparseable_True()
    {
        PasswordHasher.NeedsRehash("$2b$10$legacybcrypt").ShouldBeTrue();
    }

    [Fact]
    public void VerifyDummy_NeverThrows()
    {
        // The timing-equalizer for unknown accounts (SRS 5.3): it must
        // burn cost and stay silent.
        Should.NotThrow(() => PasswordHasher.VerifyDummy("any password"));
    }
}
