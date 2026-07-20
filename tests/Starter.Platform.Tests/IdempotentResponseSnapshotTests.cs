using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Shouldly;
using Starter.Platform.Http;
using Starter.SharedKernel;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The handler-result-to-stored-response table (LLD 7.2): value results and
/// plain objects snapshot to (status, JSON body); status-only results store
/// a JSON null body; anything unreplayable under RequireIdempotency throws
/// so the bug surfaces as a 500 instead of a corrupt replay.
/// </summary>
public class IdempotentResponseSnapshotTests
{
    private static readonly JsonSerializerOptions Web = JsonSerializerOptions.Web;

    private sealed record Payload(Guid Id, string Name);

    [Fact]
    public void OkWithValue_CapturesStatusAndCamelCaseJson()
    {
        var payload = new Payload(Guid.Parse("019a0000-0000-7000-8000-000000000001"), "thing");

        var (status, body) = IdempotentResponseSnapshot.Capture(TypedResults.Ok(payload), Web);

        status.ShouldBe(StatusCodes.Status200OK);
        body.ShouldBe("""{"id":"019a0000-0000-7000-8000-000000000001","name":"thing"}""");
    }

    [Fact]
    public void CreatedWithValue_Captures201()
    {
        var payload = new Payload(Guid.CreateVersion7(), "thing");

        var (status, body) = IdempotentResponseSnapshot.Capture(
            TypedResults.Created("/things/1", payload), Web);

        status.ShouldBe(StatusCodes.Status201Created);
        body.ShouldContain("\"name\":\"thing\"");
    }

    [Fact]
    public void NoContent_Captures204WithJsonNullBody()
    {
        var (status, body) = IdempotentResponseSnapshot.Capture(TypedResults.NoContent(), Web);

        status.ShouldBe(StatusCodes.Status204NoContent);
        body.ShouldBe("null");
    }

    [Fact]
    public void PlainObject_CapturesImplicit200()
    {
        var (status, body) = IdempotentResponseSnapshot.Capture(new Payload(Guid.CreateVersion7(), "x"), Web);

        status.ShouldBe(StatusCodes.Status200OK);
        body.ShouldContain("\"name\":\"x\"");
    }

    [Fact]
    public void Null_CapturesImplicit200WithJsonNullBody()
    {
        var (status, body) = IdempotentResponseSnapshot.Capture(null, Web);

        status.ShouldBe(StatusCodes.Status200OK);
        body.ShouldBe("null");
    }

    [Fact]
    public void StatusOf_ReportsNonSuccess_WithoutTouchingTheBody()
    {
        // The filter checks the status before any body capture, so a
        // non-2xx result passes through even when unsnapshotable.
        var context = new DefaultHttpContext();
        var error = new Error(ErrorKind.NotFound, "trip.not_found", "gone");

        IdempotentResponseSnapshot.StatusOf(error.ToProblemResult(context))
            .ShouldBe(StatusCodes.Status404NotFound);
        IdempotentResponseSnapshot.StatusOf(TypedResults.NoContent())
            .ShouldBe(StatusCodes.Status204NoContent);
        IdempotentResponseSnapshot.StatusOf(new Payload(Guid.CreateVersion7(), "x"))
            .ShouldBe(StatusCodes.Status200OK);
    }

    [Fact]
    public void TypedUnion_SuccessBranch_CapturesTheInnerResult()
    {
        // Issue #105: Results<T1,T2> implements INestedHttpResult and
        // neither status nor value interface; without unwrapping, the
        // success branch misreads as 200 and the capture throws.
        var payload = new Payload(Guid.Parse("019a0000-0000-7000-8000-000000000002"), "thing");
        Results<Created<Payload>, NotFound> union = TypedResults.Created("/things/1", payload);

        IdempotentResponseSnapshot.StatusOf(union).ShouldBe(StatusCodes.Status201Created);

        var (status, body) = IdempotentResponseSnapshot.Capture(union, Web);
        status.ShouldBe(StatusCodes.Status201Created);
        body.ShouldContain("\"name\":\"thing\"");
    }

    [Fact]
    public void TypedUnion_NonSuccessBranch_ReportsTheInnerStatus()
    {
        // The filter passes non-2xx through unstored; the union must
        // report the branch's real status, not an implicit 200.
        Results<Created<Payload>, NotFound> union = TypedResults.NotFound();

        IdempotentResponseSnapshot.StatusOf(union).ShouldBe(StatusCodes.Status404NotFound);
    }

    [Fact]
    public void StringResult_Throws()
    {
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture("plain text", Web));
    }

    [Fact]
    public void NonJsonResult_Throws()
    {
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(TypedResults.Redirect("/elsewhere"), Web));
    }

    [Fact]
    public void ContentResult_Throws()
    {
        // Issue #170: ContentHttpResult / Utf8ContentHttpResult implement
        // IStatusCodeHttpResult but not IValueHttpResult; without a content
        // case they were captured as (200, empty body) and every replay
        // silently returned nothing instead of throwing.
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(TypedResults.Text("hello"), Web));
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(
                TypedResults.Content("<p>hi</p>", "text/html"), Web));
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(TypedResults.Text("hello"u8), Web));
    }

    [Fact]
    public void UnmappedResultChannel_Throws()
    {
        // Handlers return Result (LLD section 1); endpoints must map it to
        // an IResult before it reaches the filter.
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(Result.Success(), Web));
        Should.Throw<InvalidOperationException>(
            () => IdempotentResponseSnapshot.Capture(Result.Success(42), Web));
    }
}
