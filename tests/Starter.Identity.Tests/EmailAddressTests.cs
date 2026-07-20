using Shouldly;
using Starter.Identity.Domain;
using Xunit;

namespace Starter.Identity.Tests;

public class EmailAddressTests
{
    [Theory]
    [InlineData("priya@example.com")]
    [InlineData("first.last+tag@sub.domain.co.in")]
    [InlineData("Priya@Example.com")] // uppercase domain: citext storage
    public void IsValid_ReasonableAddresses_True(string email)
    {
        EmailAddress.IsValid(email).ShouldBeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no-at-sign")]
    [InlineData("dotless@domain")]
    [InlineData("Display Name <a@b.com>")]
    [InlineData("two@ats@example.com")]
    public void IsValid_Malformed_False(string email)
    {
        EmailAddress.IsValid(email).ShouldBeFalse();
    }

    [Fact]
    public void IsValid_OverRfcLength_False()
    {
        var email = new string('a', 250) + "@example.com";

        EmailAddress.IsValid(email).ShouldBeFalse();
    }
}
