using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Starter.Identity.Mfa;

/// <summary>
/// RFC 6238 TOTP over the built-in <see cref="HMACSHA1"/> (mfa-totp.md section
/// 3): HMAC-SHA1 over the 8-byte big-endian time-step counter
/// (<c>floor(unixSeconds / 30)</c>), the standard dynamic truncation to a
/// 31-bit integer, then <c>mod 1_000_000</c> for six digits (zero-padded).
/// The algorithm is PINNED by the RFC's own Appendix B golden vectors
/// (TotpTests) rather than a new crypto dependency. No 6238 crypto is invented
/// here - only the standard construction, verified against the published
/// vectors.
/// </summary>
internal static class Totp
{
    /// <summary>The RFC 6238 time step, 30 seconds - the universal authenticator default.</summary>
    public const int StepSeconds = 30;

    private const int Digits = 6;

    private const int Modulus = 1_000_000;

    /// <summary>The current time step for an instant: <c>floor(unixSeconds / 30)</c>.</summary>
    public static long CurrentStep(DateTimeOffset now) => now.ToUnixTimeSeconds() / StepSeconds;

    /// <summary>
    /// Generates the six-digit code for a secret and a time step. The 6-digit
    /// value is the low-order six of the truncated 31-bit integer
    /// (<c>mod 1_000_000</c>), which is what real authenticators emit and what
    /// the golden vectors assert.
    /// </summary>
    public static string Generate(ReadOnlySpan<byte> secret, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);

        Span<byte> mac = stackalloc byte[HMACSHA1.HashSizeInBytes];

        // HMAC-SHA1 is not a "weak algorithm" choice here: RFC 6238 defines
        // TOTP over HMAC-SHA1, and every authenticator app (Google
        // Authenticator, 1Password, Authy) expects it. It is a MAC over a
        // high-entropy random secret, not a password hash or a collision-
        // sensitive digest, so the SHA-1 weaknesses CA5350 warns about do not
        // apply. Interoperability requires it.
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
        HMACSHA1.HashData(secret, counter, mac);
#pragma warning restore CA5350

        // Dynamic truncation (RFC 4226 section 5.3): the low nibble of the last
        // byte selects a 4-byte offset; mask the high bit to a 31-bit integer.
        var offset = mac[^1] & 0x0f;
        var binary =
            ((mac[offset] & 0x7f) << 24)
            | ((mac[offset + 1] & 0xff) << 16)
            | ((mac[offset + 2] & 0xff) << 8)
            | (mac[offset + 3] & 0xff);

        return (binary % Modulus).ToString(CultureInfo.InvariantCulture).PadLeft(Digits, '0');
    }

    /// <summary>
    /// Verifies a submitted code against a secret with a +/-1 step skew window
    /// and the replay guard. Candidate steps are the current step and its two
    /// neighbours; a candidate at or below <paramref name="lastAcceptedStep"/>
    /// is skipped (a code for an already-accepted step is a replay). The digit
    /// comparison is constant-time (<see cref="CryptographicOperations.FixedTimeEquals"/>),
    /// so no timing side-channel leaks digit-by-digit correctness. On a match,
    /// <paramref name="matchedStep"/> is the accepted step, which the caller
    /// records to advance the replay guard.
    /// </summary>
    public static bool Verify(
        ReadOnlySpan<byte> secret,
        string submittedCode,
        long currentStep,
        long? lastAcceptedStep,
        out long matchedStep)
    {
        matchedStep = 0;
        if (string.IsNullOrEmpty(submittedCode))
        {
            return false;
        }

        var submitted = Encoding.ASCII.GetBytes(submittedCode);
        for (var offset = -1; offset <= 1; offset++)
        {
            var candidate = currentStep + offset;
            if (lastAcceptedStep is long last && candidate <= last)
            {
                // Replay guard: this step was already consumed. Accepted steps
                // are monotonically non-decreasing across genuine logins, so
                // this never rejects the next legitimate step, only a replay.
                continue;
            }

            var expected = Encoding.ASCII.GetBytes(Generate(secret, candidate));
            if (CryptographicOperations.FixedTimeEquals(expected, submitted))
            {
                matchedStep = candidate;
                return true;
            }
        }

        return false;
    }
}
