using Shouldly;
using Xunit;

namespace Starter.SharedKernel.Tests;

public class ResultTests
{
    private static readonly Error NotFound =
        new(ErrorKind.NotFound, "sample.not_found", "Sample does not exist or the caller cannot access it.");

    [Fact]
    public void Success_NoValue_IsSuccessWithNoError()
    {
        var result = Result.Success();

        result.IsSuccess.ShouldBeTrue();
        result.IsFailure.ShouldBeFalse();
        Should.Throw<InvalidOperationException>(() => result.Error);
    }

    [Fact]
    public void Failure_NoValue_CarriesError()
    {
        var result = Result.Failure(NotFound);

        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBe(NotFound);
    }

    [Fact]
    public void Failure_NullError_ThrowsArgumentNull()
    {
        Should.Throw<ArgumentNullException>(() => Result.Failure(null!));
    }

    [Fact]
    public void Success_WithValue_CarriesValue()
    {
        var result = Result.Success(42);

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe(42);
        Should.Throw<InvalidOperationException>(() => result.Error);
    }

    [Fact]
    public void Failure_WithValueType_ValueAccessThrowsInvalidOperation()
    {
        var result = Result.Failure<int>(NotFound);

        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBe(NotFound);
        Should.Throw<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Failure_GenericNullError_ThrowsArgumentNull()
    {
        Should.Throw<ArgumentNullException>(() => Result.Failure<int>(null!));
    }

    [Fact]
    public void ImplicitConversion_FromValue_CreatesSuccess()
    {
        Result<string> result = "goa";

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe("goa");
    }

    [Fact]
    public void ImplicitConversion_FromError_CreatesFailure()
    {
        Result<string> result = NotFound;

        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBe(NotFound);
    }

    [Fact]
    public void Match_Success_CallsOnSuccessOnly()
    {
        var outcome = Result.Success().Match(() => "ok", error => $"failed: {error.Code}");

        outcome.ShouldBe("ok");
    }

    [Fact]
    public void Match_Failure_CallsOnFailureOnly()
    {
        var outcome = Result.Failure(NotFound).Match(() => "ok", error => error.Code);

        outcome.ShouldBe("sample.not_found");
    }

    [Fact]
    public void Match_GenericSuccess_ReceivesValue()
    {
        var outcome = Result.Success(21).Match(value => value * 2, error => 0);

        outcome.ShouldBe(42);
    }

    [Fact]
    public void Match_GenericFailure_ReceivesError()
    {
        var outcome = Result.Failure<int>(NotFound).Match(value => "ok", error => error.Code);

        outcome.ShouldBe("sample.not_found");
    }

    [Fact]
    public void Match_NullCallbacks_ThrowArgumentNull()
    {
        Should.Throw<ArgumentNullException>(
            () => Result.Success().Match(null!, error => "x"));
        Should.Throw<ArgumentNullException>(
            () => Result.Success(1).Match(value => "x", null!));
    }
}
