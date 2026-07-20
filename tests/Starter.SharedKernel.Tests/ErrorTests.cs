using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class ErrorTests
{
    [Fact]
    public void Ctor_ValidFields_SetsProperties()
    {
        var error = new Error(ErrorKind.Conflict, "sample.version_conflict", "Sample was modified concurrently.");

        error.Kind.ShouldBe(ErrorKind.Conflict);
        error.Code.ShouldBe("sample.version_conflict");
        error.Message.ShouldBe("Sample was modified concurrently.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Ctor_BlankCode_ThrowsArgument(string? code)
    {
        Should.Throw<ArgumentException>(
            () => new Error(ErrorKind.Validation, code!, "message"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Ctor_BlankMessage_ThrowsArgument(string? message)
    {
        Should.Throw<ArgumentException>(
            () => new Error(ErrorKind.Validation, "sample.invalid_field", message!));
    }

    [Fact]
    public void Equals_SameFields_Equal()
    {
        var left = new Error(ErrorKind.NotFound, "sample.not_found", "Missing.");
        var right = new Error(ErrorKind.NotFound, "sample.not_found", "Missing.");

        left.ShouldBe(right);
    }
}
