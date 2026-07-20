namespace Starter.SharedKernel;

/// <summary>
/// An ISO 4217 alphabetic currency code (INV-1). The kernel validates shape
/// only (exactly three ASCII uppercase letters) and never restricts the
/// currency set: scoping launch to INR is API-boundary validation (ADR-0004),
/// not a kernel rule.
/// </summary>
public readonly record struct CurrencyCode
{
    /// <summary>Indian rupee, the launch trip currency (ADR-0004).</summary>
    public static readonly CurrencyCode Inr = new("INR");

    private readonly string? _value;

    public CurrencyCode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!IsThreeUppercaseAsciiLetters(value))
        {
            throw new ArgumentException(
                $"Currency code must be exactly three ASCII uppercase letters (ISO 4217), got '{value}'.",
                nameof(value));
        }

        _value = value;
    }

    /// <summary>
    /// The three-letter code. Throws on a default-constructed instance:
    /// an uninitialized currency in a money path is a bug, not a value.
    /// </summary>
    public string Value =>
        _value ?? throw new InvalidOperationException(
            "CurrencyCode was default-constructed; a currency code must be created from a three-letter ISO 4217 code.");

    /// <summary>
    /// The code, or an empty string for a default-constructed instance:
    /// ToString must never throw (it feeds debuggers and log formatting).
    /// Consumers that need the guarantee read <see cref="Value"/>.
    /// </summary>
    public override string ToString() => _value ?? string.Empty;

    private static bool IsThreeUppercaseAsciiLetters(string value)
    {
        if (value.Length != 3)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is < 'A' or > 'Z')
            {
                return false;
            }
        }

        return true;
    }
}
