using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Shouldly;
using Starter.Platform.Http;
using Starter.SharedKernel;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The mapping table as unit tests: every ErrorKind lands in the
/// problem+json envelope with its documented status and starter:* slug,
/// and every envelope carries a traceId. This is the contract the
/// ErrorKind XML docs promise.
/// </summary>
public class StarterProblemsTests
{
    private static DefaultHttpContext NewHttpContext() =>
        new() { TraceIdentifier = "trace-test-0001" };

    public static TheoryData<ErrorKind, string, int, string> MappingTable => new()
    {
        { ErrorKind.Validation, "sample.field_mismatch", StatusCodes.Status422UnprocessableEntity, ProblemTypes.Validation },
        { ErrorKind.NotFound, "sample.not_found", StatusCodes.Status404NotFound, ProblemTypes.NotFound },
        { ErrorKind.Conflict, "sample.version_conflict", StatusCodes.Status409Conflict, ProblemTypes.VersionConflict },
        { ErrorKind.Conflict, "idempotency.in_flight", StatusCodes.Status409Conflict, ProblemTypes.IdempotencyInFlight },
        { ErrorKind.Unauthorized, "auth.token_expired", StatusCodes.Status401Unauthorized, ProblemTypes.Unauthorized },
        { ErrorKind.RateLimited, "rate.limit_exceeded", StatusCodes.Status429TooManyRequests, ProblemTypes.RateLimited },
    };

    [Theory]
    [MemberData(nameof(MappingTable))]
    public void From_MapsKindAndCode_ToDocumentedStatusAndSlug(
        ErrorKind kind, string code, int expectedStatus, string expectedType)
    {
        var error = new Error(kind, code, "developer prose");

        var problem = StarterProblems.From(error, NewHttpContext());

        problem.Status.ShouldBe(expectedStatus);
        problem.Type.ShouldBe(expectedType);
        problem.Title.ShouldNotBeNullOrWhiteSpace();
        problem.Detail.ShouldBe("developer prose");
    }

    [Fact]
    public void From_EveryErrorKind_HasAMapping()
    {
        // A kind added to the SharedKernel without a mapped slug must fail
        // here, not at runtime (ErrorKind XML docs: both change together).
        foreach (var kind in Enum.GetValues<ErrorKind>())
        {
            var error = new Error(kind, "any.code", "message");

            Should.NotThrow(() => StarterProblems.From(error, NewHttpContext()));
        }
    }

    [Fact]
    public void From_CarriesTraceId()
    {
        var error = new Error(ErrorKind.NotFound, "sample.not_found", "message");

        var problem = StarterProblems.From(error, NewHttpContext());

        problem.Extensions.ShouldContainKey(StarterProblems.TraceIdExtension);
        problem.Extensions[StarterProblems.TraceIdExtension]
            .ShouldBeOfType<string>()
            .ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Validation_CarriesFieldToMessagesMap()
    {
        var errors = new Dictionary<string, string[]>
        {
            ["Idempotency-Key"] = ["The Idempotency-Key header is required on mutating endpoints."],
        };

        var problem = StarterProblems.Validation(NewHttpContext(), errors);

        problem.Status.ShouldBe(StatusCodes.Status422UnprocessableEntity);
        problem.Type.ShouldBe(ProblemTypes.Validation);
        problem.Extensions[StarterProblems.ErrorsExtension].ShouldBe(errors);
    }

    [Fact]
    public void IdempotencyInFlight_Is409WithItsSlug()
    {
        var problem = StarterProblems.IdempotencyInFlight(NewHttpContext());

        problem.Status.ShouldBe(StatusCodes.Status409Conflict);
        problem.Type.ShouldBe(ProblemTypes.IdempotencyInFlight);
    }

    [Fact]
    public void Internal_Is500WithNoDetail()
    {
        // The 500 body carries only slug, title, and traceId; whatever blew
        // up stays in the logs (no raw exception reaches a client).
        var problem = StarterProblems.Internal(NewHttpContext());

        problem.Status.ShouldBe(StatusCodes.Status500InternalServerError);
        problem.Type.ShouldBe(ProblemTypes.Internal);
        problem.Detail.ShouldBeNull();
    }

    [Theory]
    [InlineData(StatusCodes.Status401Unauthorized, ProblemTypes.Unauthorized)]
    [InlineData(StatusCodes.Status403Forbidden, ProblemTypes.Forbidden)]
    [InlineData(StatusCodes.Status404NotFound, ProblemTypes.NotFound)]
    [InlineData(StatusCodes.Status405MethodNotAllowed, ProblemTypes.MethodNotAllowed)]
    [InlineData(StatusCodes.Status415UnsupportedMediaType, ProblemTypes.UnsupportedMediaType)]
    [InlineData(StatusCodes.Status429TooManyRequests, ProblemTypes.RateLimited)]
    [InlineData(StatusCodes.Status406NotAcceptable, ProblemTypes.BadRequest)] // unlisted 4xx falls back
    [InlineData(StatusCodes.Status502BadGateway, ProblemTypes.Internal)] // 5xx keeps the internal slug
    public void ForStatus_MapsBareStatuses_ToTheirSlugs_PreservingTheStatus(int statusCode, string expectedType)
    {
        // The status-code-pages half of the problem envelope: notably
        // 429 keeps its rate-limited slug - a bare 429 from the
        // rate limiter must never read as "the request could not be read".
        var problem = StarterProblems.ForStatus(NewHttpContext(), statusCode);

        problem.Status.ShouldBe(statusCode);
        problem.Type.ShouldBe(expectedType);
        problem.Title.ShouldNotBeNullOrWhiteSpace();
        problem.Extensions.ShouldContainKey(StarterProblems.TraceIdExtension);
    }

    [Fact]
    public void ToProblemResult_WrapsTheEnvelope()
    {
        var error = new Error(ErrorKind.NotFound, "sample.not_found", "message");

        var result = error.ToProblemResult(NewHttpContext());

        var problemResult = result.ShouldBeOfType<ProblemHttpResult>();
        problemResult.StatusCode.ShouldBe(StatusCodes.Status404NotFound);
        problemResult.ProblemDetails.Type.ShouldBe(ProblemTypes.NotFound);
    }
}
