namespace Starter.SharedKernel;

/// <summary>
/// Thrown when arithmetic or comparison combines two different currencies.
/// Amounts are normalized to the trip currency at the API boundary, so a
/// mismatch reaching the kernel is a programming bug: it throws instead of
/// returning a <see cref="Result"/> (LLD section 1: exceptions are for bugs,
/// not flow). Joda-Money and NodaMoney make the same call.
/// </summary>
public sealed class CurrencyMismatchException : InvalidOperationException
{
    public CurrencyMismatchException(CurrencyCode left, CurrencyCode right)
        : base($"Cannot combine amounts in different currencies: {left} and {right}.")
    {
    }
}
