using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class MoneyTests
{
    private static readonly CurrencyCode Inr = CurrencyCode.Inr;
    private static readonly CurrencyCode Usd = new("USD");

    [Fact]
    public void Ctor_ValidAmountAndCurrency_SetsProperties()
    {
        var money = new Money(12345, Inr);

        money.MinorUnits.ShouldBe(12345);
        money.Currency.ShouldBe(Inr);
    }

    [Fact]
    public void Ctor_NegativeAmount_IsValid()
    {
        // Ledger deltas and balances are signed (doc 07).
        var money = new Money(-500, Inr);

        money.IsNegative.ShouldBeTrue();
    }

    [Fact]
    public void Ctor_DefaultCurrencyCode_Throws()
    {
        Should.Throw<InvalidOperationException>(() => new Money(100, default));
    }

    [Fact]
    public void Zero_Inr_IsZeroWithCurrency()
    {
        var zero = Money.Zero(Inr);

        zero.IsZero.ShouldBeTrue();
        zero.MinorUnits.ShouldBe(0);
        zero.Currency.ShouldBe(Inr);
    }

    [Fact]
    public void Add_SameCurrency_SumsMinorUnits()
    {
        var sum = new Money(300, Inr) + new Money(450, Inr);

        sum.ShouldBe(new Money(750, Inr));
    }

    [Fact]
    public void Add_DifferentCurrencies_ThrowsCurrencyMismatch()
    {
        Should.Throw<CurrencyMismatchException>(
            () => new Money(100, Inr) + new Money(100, Usd));
    }

    [Fact]
    public void Add_OverflowingInt64_ThrowsOverflow()
    {
        Should.Throw<OverflowException>(
            () => new Money(long.MaxValue, Inr) + new Money(1, Inr));
    }

    [Fact]
    public void Subtract_SameCurrency_SubtractsMinorUnits()
    {
        var difference = new Money(750, Inr) - new Money(450, Inr);

        difference.ShouldBe(new Money(300, Inr));
    }

    [Fact]
    public void Subtract_DifferentCurrencies_ThrowsCurrencyMismatch()
    {
        Should.Throw<CurrencyMismatchException>(
            () => new Money(100, Inr) - new Money(100, Usd));
    }

    [Fact]
    public void Subtract_OverflowingInt64_ThrowsOverflow()
    {
        Should.Throw<OverflowException>(
            () => new Money(long.MinValue, Inr) - new Money(1, Inr));
    }

    [Fact]
    public void Negate_PositiveAmount_ReturnsNegative()
    {
        var negated = -new Money(500, Inr);

        negated.ShouldBe(new Money(-500, Inr));
    }

    [Fact]
    public void Negate_LongMinValue_ThrowsOverflow()
    {
        Should.Throw<OverflowException>(() => new Money(long.MinValue, Inr).Negate());
    }

    [Fact]
    public void CompareTo_SameCurrency_OrdersByAmount()
    {
        var smaller = new Money(100, Inr);
        var larger = new Money(200, Inr);

        smaller.CompareTo(larger).ShouldBeLessThan(0);
        (smaller < larger).ShouldBeTrue();
        (larger > smaller).ShouldBeTrue();
        (smaller <= larger).ShouldBeTrue();
        (larger >= smaller).ShouldBeTrue();
    }

    [Fact]
    public void CompareTo_DifferentCurrencies_ThrowsCurrencyMismatch()
    {
        Should.Throw<CurrencyMismatchException>(
            () => new Money(100, Inr).CompareTo(new Money(100, Usd)));
    }

    [Fact]
    public void CompareTo_TwoDefaultInstances_ThrowsInvalidOperation()
    {
        // Both defaults carry equal (default) currencies, so the mismatch
        // check alone would pass; the guard must reject currencyless
        // operands outright rather than let the comparison return 0.
        Should.Throw<InvalidOperationException>(
            () => default(Money).CompareTo(default));
    }

    [Fact]
    public void Add_TwoDefaultInstances_ThrowsInvalidOperation()
    {
        Should.Throw<InvalidOperationException>(() => default(Money) + default(Money));
    }

    [Fact]
    public void Equals_SameAmountSameCurrency_Equal()
    {
        new Money(100, Inr).ShouldBe(new Money(100, Inr));
    }

    [Fact]
    public void Equals_SameAmountDifferentCurrency_NotEqual()
    {
        new Money(100, Inr).ShouldNotBe(new Money(100, Usd));
    }

    [Fact]
    public void ToString_AmountAndCurrency_ReadsCurrencyFirst()
    {
        new Money(12345, Inr).ToString().ShouldBe("INR 12345");
    }
}
