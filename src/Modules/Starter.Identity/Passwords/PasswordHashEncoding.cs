using System.Globalization;

namespace Starter.Identity.Passwords;

/// <summary>
/// The PHC string format for Argon2id hashes:
/// <c>$argon2id$v=19$m=..,t=..,p=..$&lt;b64 salt&gt;$&lt;b64 hash&gt;</c>
/// (the reference-implementation convention, also what libsodium and
/// passlib emit). Parameters ride inside every hash so verification never
/// consults current policy and rehash-on-login can move parameters
/// gradually (doc 10 4.1).
/// </summary>
internal static class PasswordHashEncoding
{
    private const string Prefix = "$argon2id$v=19$";

    public static string Format(Argon2Parameters parameters, byte[] salt, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(hash);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Prefix}m={parameters.MemoryKibibytes},t={parameters.Iterations},p={parameters.Parallelism}${Base64(salt)}${Base64(hash)}");
    }

    public static bool TryParse(
        string encoded,
        out Argon2Parameters parameters,
        out byte[] salt,
        out byte[] hash)
    {
        parameters = default;
        salt = [];
        hash = [];

        if (string.IsNullOrEmpty(encoded) || !encoded.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = encoded[Prefix.Length..].Split('$');
        if (parts.Length != 3)
        {
            return false;
        }

        if (!TryParseParameters(parts[0], out parameters))
        {
            return false;
        }

        try
        {
            salt = FromBase64(parts[1]);
            hash = FromBase64(parts[2]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length > 0 && hash.Length > 0;
    }

    private static bool TryParseParameters(string segment, out Argon2Parameters parameters)
    {
        parameters = default;
        int? memory = null, iterations = null, parallelism = null;

        foreach (var pair in segment.Split(','))
        {
            var keyValue = pair.Split('=');
            if (keyValue.Length != 2
                || !int.TryParse(keyValue[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                || value <= 0)
            {
                return false;
            }

            switch (keyValue[0])
            {
                case "m":
                    memory = value;
                    break;
                case "t":
                    iterations = value;
                    break;
                case "p":
                    parallelism = value;
                    break;
                default:
                    return false;
            }
        }

        if (memory is null || iterations is null || parallelism is null)
        {
            return false;
        }

        parameters = new Argon2Parameters(memory.Value, iterations.Value, parallelism.Value);
        return true;
    }

    // PHC uses unpadded standard base64.
    private static string Base64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static byte[] FromBase64(string value) =>
        Convert.FromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '='));
}

/// <summary>Argon2id cost parameters as stored per-hash (doc 10 4.1).</summary>
/// <param name="MemoryKibibytes">Memory cost in KiB (PHC `m`).</param>
/// <param name="Iterations">Passes over memory (PHC `t`).</param>
/// <param name="Parallelism">Lanes (PHC `p`).</param>
internal readonly record struct Argon2Parameters(int MemoryKibibytes, int Iterations, int Parallelism);
