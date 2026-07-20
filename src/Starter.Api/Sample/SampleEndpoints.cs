using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Sample;
using Starter.Platform.Http;

namespace Starter.Api.Sample;

/// <summary>
/// HTTP composition for the Sample module's create / get-by-id slices: the
/// worked example of how a module's endpoints hang off the versioned route
/// group. Business rules live behind <see cref="ISampleApi"/>; this layer
/// never touches the module's internals (ADR-0011). It maps onto a route
/// group the composition root has already bound to an API version, so the
/// full path is <c>/api/v1/sample/notes</c>.
/// </summary>
public static class SampleEndpoints
{
    public static IEndpointRouteBuilder MapSampleEndpoints(this IEndpointRouteBuilder versionedGroup)
    {
        ArgumentNullException.ThrowIfNull(versionedGroup);

        // Demonstration module: the notes routes are open. A real module
        // gates its writes with .RequireAuthorization() - see the Identity
        // endpoints for the authenticated pattern.
        var notes = versionedGroup.MapGroup("/sample/notes").AllowAnonymous();

        notes.MapPost("/", CreateNoteAsync);
        notes.MapGet("/{id:guid}", GetNoteByIdAsync);

        return versionedGroup;
    }

    private static async Task<IResult> CreateNoteAsync(
        CreateNoteRequest request,
        ISampleApi sample,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title))
        {
            errors["title"] = ["Title is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Body))
        {
            errors["body"] = ["Body is required."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.Problem(StarterProblems.Validation(http, errors));
        }

        var result = await sample.CreateNoteAsync(request.Title!, request.Body!, cancellationToken);
        return result.Match(
            id => Results.Created($"/api/v1/sample/notes/{id}", new CreateNoteResponse(id)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> GetNoteByIdAsync(
        Guid id,
        ISampleApi sample,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await sample.GetNoteAsync(id, cancellationToken);
        return result.Match(
            note => Results.Ok(new NoteResponse(note.Id, note.Title, note.Body, note.CreatedAt, note.UpdatedAt)),
            error => error.ToProblemResult(http));
    }
}

/// <summary>POST /api/v1/sample/notes body.</summary>
public sealed record CreateNoteRequest(string? Title, string? Body);

/// <summary>POST /api/v1/sample/notes success: the new note's id.</summary>
public sealed record CreateNoteResponse(Guid Id);

/// <summary>GET /api/v1/sample/notes/{id} success.</summary>
public sealed record NoteResponse(Guid Id, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);
