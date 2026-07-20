using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Starter.Identity.Passwords;

/// <summary>
/// Argon2id password hashing per OWASP-baseline parameters:
/// memory 19 MiB, iterations 2, parallelism 1. Parameters are stored
/// per-hash (PHC format) and <see cref="NeedsRehash"/> drives
/// rehash-on-login, so parameter upgrades are gradual and free. Static by
/// design: pure functions over (password, hash), no state to inject.
/// </summary>
internal static class PasswordHasher
{
    /// <summary>Current policy. Moving these is a deliberate, reviewed change.</summary>
    internal static readonly Argon2Parameters CurrentParameters = new(
        MemoryKibibytes: 19 * 1024,
        Iterations: 2,
        Parallelism: 1);

    private const int SaltLength = 16;

    private const int HashLength = 32;

    // A throwaway hash verified against mismatching input to give the
    // user-unknown paths the same Argon2 cost as a real verification
    // (login and register stay timing-uniform across existing and
    // unknown accounts - the no-account-enumeration edge).
    private static readonly Lazy<string> DummyHash = new(
        () => Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(24))),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public static string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Derive(password, salt, CurrentParameters);
        return PasswordHashEncoding.Format(CurrentParameters, salt, hash);
    }

    public static bool Verify(string password, string encodedHash)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentException.ThrowIfNullOrEmpty(encodedHash);

        if (!PasswordHashEncoding.TryParse(encodedHash, out var parameters, out var salt, out var expected))
        {
            return false;
        }

        var actual = Derive(password, salt, parameters);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// True when the stored hash predates the current parameters; the
    /// login path rehashes with the just-verified password.
    /// </summary>
    public static bool NeedsRehash(string encodedHash)
    {
        ArgumentException.ThrowIfNullOrEmpty(encodedHash);

        return !PasswordHashEncoding.TryParse(encodedHash, out var parameters, out _, out _)
            || parameters != CurrentParameters;
    }

    /// <summary>
    /// Burns one full Argon2 verification without revealing anything:
    /// called on paths where no stored hash exists so response timing does
    /// not distinguish existing from unknown accounts.
    /// </summary>
    public static void VerifyDummy(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        Verify(password, DummyHash.Value);
    }

    /// <summary>
    /// Mints a hash under explicit (e.g. legacy) parameters. Test hook for
    /// the rehash-on-login path: production code always hashes with
    /// <see cref="CurrentParameters"/> via <see cref="Hash"/>.
    /// </summary>
    internal static string HashWith(Argon2Parameters parameters, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        return PasswordHashEncoding.Format(parameters, salt, Derive(password, salt, parameters));
    }

    private static byte[] Derive(string password, byte[] salt, Argon2Parameters parameters)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = parameters.MemoryKibibytes,
            Iterations = parameters.Iterations,
            DegreeOfParallelism = parameters.Parallelism,
        };
        return argon2.GetBytes(HashLength);
    }
}
