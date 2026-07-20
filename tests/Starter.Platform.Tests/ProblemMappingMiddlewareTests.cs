using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using Starter.Platform.Http;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The exception half of the mapping contract: any unhandled exception
/// becomes a 500 problem envelope with no exception text on the wire,
/// successful responses pass untouched, and a response already on the
/// wire is aborted rather than corrupted.
/// </summary>
public class ProblemMappingMiddlewareTests
{
    private static ProblemMappingMiddleware NewMiddleware(RequestDelegate next) =>
        new(
            next,
            new PlatformHttpMetrics(),
            Options.Create(new JsonOptions()),
            NullLogger<ProblemMappingMiddleware>.Instance);

    private static DefaultHttpContext NewHttpContext()
    {
        var context = new DefaultHttpContext { TraceIdentifier = "trace-test-0001" };
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Fact]
    public async Task UnhandledException_Becomes500ProblemJson_WithoutLeakingTheException()
    {
        const string secret = "connection string with credentials";
        var middleware = NewMiddleware(_ => throw new InvalidOperationException(secret));
        var context = NewHttpContext();

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status500InternalServerError);
        context.Response.ContentType.ShouldStartWith("application/problem+json");

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        var body = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        body.ShouldNotContain(secret);
        body.ShouldNotContain(nameof(InvalidOperationException));

        using var problem = JsonDocument.Parse(body);
        problem.RootElement.GetProperty("type").GetString().ShouldBe(ProblemTypes.Internal);
        problem.RootElement.GetProperty("status").GetInt32().ShouldBe(500);
        problem.RootElement.GetProperty("traceId").GetString().ShouldNotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData(StatusCodes.Status400BadRequest)]
    [InlineData(StatusCodes.Status413PayloadTooLarge)]
    [InlineData(StatusCodes.Status431RequestHeaderFieldsTooLarge)]
    public async Task BadHttpRequestException_KeepsTheClientStatus_AsABadRequestProblem(int statusCode)
    {
        // A request-reading fault is a client error; mapping it to 500
        // starter:internal misreports it as a server bug. The framework's
        // status is preserved and its message stays off the wire.
        const string frameworkDetail = "Failed to read parameter \"Payload payload\" from the request body as JSON.";
        var middleware = NewMiddleware(_ => throw new BadHttpRequestException(frameworkDetail, statusCode));
        var context = NewHttpContext();

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldBe(statusCode);
        context.Response.ContentType.ShouldStartWith("application/problem+json");

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        var body = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        body.ShouldNotContain(frameworkDetail);

        using var problem = JsonDocument.Parse(body);
        problem.RootElement.GetProperty("type").GetString().ShouldBe(ProblemTypes.BadRequest);
        problem.RootElement.GetProperty("status").GetInt32().ShouldBe(statusCode);
        problem.RootElement.GetProperty("traceId").GetString().ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task SuccessfulResponse_PassesThroughUntouched()
    {
        var middleware = NewMiddleware(async ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status201Created;
            await ctx.Response.WriteAsync("""{"ok":true}""");
        });
        var context = NewHttpContext();

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status201Created);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        (await reader.ReadToEndAsync(TestContext.Current.CancellationToken))
            .ShouldBe("""{"ok":true}""");
    }

    [Fact]
    public async Task ExceptionAfterResponseStarted_Rethrows()
    {
        var middleware = NewMiddleware(ctx =>
        {
            // Simulate bytes already on the wire: swapping in a problem body
            // now would corrupt the response, so the middleware must rethrow.
            ctx.Features.Set<IHttpResponseFeature>(new StartedResponseFeature());
            throw new InvalidOperationException("too late");
        });

        await Should.ThrowAsync<InvalidOperationException>(
            () => middleware.InvokeAsync(NewHttpContext()));
    }

    [Fact]
    public async Task CancellationOfAnAbortedRequest_IsNotMapped()
    {
        using var aborted = new CancellationTokenSource();
        await aborted.CancelAsync();
        var context = NewHttpContext();
        context.RequestAborted = aborted.Token;
        var middleware = NewMiddleware(_ => throw new OperationCanceledException());

        // The client is gone; the middleware must not fabricate a 500.
        await Should.ThrowAsync<OperationCanceledException>(
            () => middleware.InvokeAsync(context));
    }

    private sealed class StartedResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; } = StatusCodes.Status200OK;

        public string? ReasonPhrase { get; set; }

        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();

        public Stream Body { get; set; } = Stream.Null;

        public bool HasStarted => true;

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }

        public void OnCompleted(Func<object, Task> callback, object state)
        {
        }
    }
}
