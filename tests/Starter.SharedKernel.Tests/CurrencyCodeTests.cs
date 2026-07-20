using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class CurrencyCodeTests
{
    [Theory]
    [InlineData("INR")]
    [InlineData("USD")]
    [InlineData("EUR")]
    [InlineData("XXX")]
    public void Ctor_ThreeUppercaseAsciiLetters_Succeeds(string code)
    {
        var currency = new CurrencyCode(code);

        currency.Value.ShouldBe(code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("IN")]
    [InlineData("INRR")]
    [InlineData("inr")]
    [InlineData("iNR")]
    [InlineData("IN1")]
    [InlineData("IN ")]
    [InlineData("IÑR")]
    public void Ctor_NotThreeUppercaseAsciiLetters_ThrowsArgument(string code)
    {
        Should.Throw<ArgumentException>(() => new CurrencyCode(code));
    }

    [Fact]
    public void Ctor_Null_ThrowsArgumentNull()
    {
        Should.Throw<ArgumentNullException>(() => new CurrencyCode(null!));
    }

    [Fact]
    public void Value_DefaultConstructedInstance_ThrowsInvalidOperation()
    {
        // default(CurrencyCode) bypasses validation; reading it is a bug.
        Should.Throw<InvalidOperationException>(() => default(CurrencyCode).Value);
    }

    [Fact]
    public void Equals_SameCode_Equal()
    {
        new CurrencyCode("INR").ShouldBe(CurrencyCode.Inr);
    }

    [Fact]
    public void Equals_DifferentCode_NotEqual()
    {
        new CurrencyCode("USD").ShouldNotBe(CurrencyCode.Inr);
    }

    [Fact]
    public void ToString_ValidCode_ReturnsCode()
    {
        CurrencyCode.Inr.ToString().ShouldBe("INR");
    }

    [Fact]
    public void ToString_DefaultConstructedInstance_ReturnsEmptyWithoutThrowing()
    {
        // ToString feeds debuggers and log formatting, so unlike Value it
        // must never throw; empty is the honest rendering of "nothing".
        default(CurrencyCode).ToString().ShouldBe(string.Empty);
    }
}
