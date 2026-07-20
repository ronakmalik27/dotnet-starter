namespace Starter.SharedKernel;

/// <summary>
/// A monetary amount: integer minor units plus an ISO 4217 currency code
/// (INV-1: no float or double anywhere in the money path). Negative amounts
/// are valid - ledger deltas and balances are signed. All arithmetic is
/// checked: Int64 overflow throws instead of corrupting an amount. API-level
/// validation caps amounts at 10^12 minor units (LLD 2.2), so overflow here
/// is always a bug, never data.
/// </summary>
public readonly record struct Money : IComparable<Money>
{
    public Money(long minorUnits, CurrencyCode currency)
    {
        // Touching Value rejects a default-constructed CurrencyCode early,
        // so no Money instance can carry a currencyless amount.
        _ = currency.Value;
        MinorUnits = minorUnits;
        Currency = currency;
    }

    public long MinorUnits { get; }

    public CurrencyCode Currency { get; }

    public bool IsZero => MinorUnits == 0;

    public bool IsNegative => MinorUnits < 0;

    public bool IsPositive => MinorUnits > 0;

    public static Money Zero(CurrencyCode currency) => new(0, currency);

    public static Money operator +(Money left, Money right) => left.Add(right);

    public static Money operator -(Money left, Money right) => left.Subtract(right);

    public static Money operator -(Money value) => value.Negate();

    public static bool operator <(Money left, Money right) => left.CompareTo(right) < 0;

    public static bool operator >(Money left, Money right) => left.CompareTo(right) > 0;

    public static bool operator <=(Money left, Money right) => left.CompareTo(right) <= 0;

    public static bool operator >=(Money left, Money right) => left.CompareTo(right) >= 0;

    public Money Add(Money other)
    {
        EnsureSameCurrency(this, other);
        return new Money(checked(MinorUnits + other.MinorUnits), Currency);
    }

    public Money Subtract(Money other)
    {
        EnsureSameCurrency(this, other);
        return new Money(checked(MinorUnits - other.MinorUnits), Currency);
    }

    public Money Negate() => new(checked(-MinorUnits), Currency);

    /// <summary>
    /// Orders by amount within one currency. Comparing across currencies
    /// throws <see cref="CurrencyMismatchException"/>: unlike equality
    /// (where different currencies are simply not equal), there is no
    /// meaningful order between currencies.
    /// </summary>
    public int CompareTo(Money other)
    {
        EnsureSameCurrency(this, other);
        return MinorUnits.CompareTo(other.MinorUnits);
    }

    public override string ToString() => $"{Currency} {MinorUnits}";

    private static void EnsureSameCurrency(Money left, Money right)
    {
        // Touching Value rejects default-constructed operands: two
        // default(Money) instances carry equal (default) currencies, so the
        // mismatch check alone would let a currencyless comparison succeed.
        _ = left.Currency.Value;
        _ = right.Currency.Value;

        if (left.Currency != right.Currency)
        {
            throw new CurrencyMismatchException(left.Currency, right.Currency);
        }
    }
}
