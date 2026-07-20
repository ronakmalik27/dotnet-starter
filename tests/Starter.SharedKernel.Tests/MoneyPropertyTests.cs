using CsCheck;
using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

/// <summary>
/// CsCheck properties for Money arithmetic (doc 12 section 2: every money
/// primitive gets property coverage before anything builds on it). Amounts
/// are generated within the LLD 2.2 validation cap (|amount| &lt;= 10^12
/// minor units), so sums of generated lists stay far from Int64 overflow -
/// overflow behavior itself is unit-tested in <see cref="MoneyTests"/>.
/// Seeds print on failure and replay via the CsCheck seed environment
/// variable (doc 12 section 12).
/// </summary>
public class MoneyPropertyTests
{
    private const long AmountCap = 1_000_000_000_000; // LLD 2.2: 10^12

    private static readonly CurrencyCode Inr = CurrencyCode.Inr;

    private static readonly Gen<Money> GenMoney =
        Gen.Long[-AmountCap, AmountCap].Select(minor => new Money(minor, Inr));

    [Fact]
    public void Add_AnyTwoAmounts_Commutes()
    {
        Gen.Select(GenMoney, GenMoney)
            .Sample((a, b) => (a + b).ShouldBe(b + a));
    }

    [Fact]
    public void Add_AnyThreeAmounts_Associates()
    {
        Gen.Select(GenMoney, GenMoney, GenMoney)
            .Sample((a, b, c) => ((a + b) + c).ShouldBe(a + (b + c)));
    }

    [Fact]
    public void Add_Zero_IsIdentity()
    {
        GenMoney.Sample(a => (a + Money.Zero(Inr)).ShouldBe(a));
    }

    [Fact]
    public void Add_ThenSubtractSameAmount_RoundTrips()
    {
        Gen.Select(GenMoney, GenMoney)
            .Sample((a, b) => ((a + b) - b).ShouldBe(a));
    }

    [Fact]
    public void Add_OwnNegation_IsZero()
    {
        GenMoney.Sample(a => (a + (-a)).ShouldBe(Money.Zero(Inr)));
    }

    [Fact]
    public void Sum_AnyAmountList_ConservesMinorUnitTotal()
    {
        // Conservation: folding Money addition equals summing the raw minor
        // units - Money arithmetic neither creates nor destroys paise.
        // 1000 amounts capped at 10^12 stay well inside Int64.
        Gen.Long[-AmountCap, AmountCap].List[0, 1000]
            .Sample(minors =>
            {
                var total = minors.Aggregate(
                    Money.Zero(Inr),
                    (acc, minor) => acc + new Money(minor, Inr));

                total.MinorUnits.ShouldBe(minors.Sum());
            });
    }

    [Fact]
    public void CompareTo_AnyTwoAmounts_MatchesMinorUnitOrder()
    {
        Gen.Select(GenMoney, GenMoney)
            .Sample((a, b) => a.CompareTo(b).ShouldBe(a.MinorUnits.CompareTo(b.MinorUnits)));
    }
}
