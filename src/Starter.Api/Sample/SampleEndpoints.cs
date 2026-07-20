using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Sample;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Sample;

/// <summary>
/// HTTP composition for the Sample module's create / get / delete slices: the
/// worked example of an authenticated, owner-scoped resource. Every note is
/// owned by the caller who created it; reads and deletes are authorized per
/// request against that owner with the resource-based
/// <see cref="ResourceOperations"/> requirements - the access token carries
/// no roles, so authorization is resolved against the entity, not the claim.
/// Business rules live behind <see cref="ISampleApi"/>; this layer never
/// touches the module's internals. It maps onto a route group the composition
/// root has already bound to an API version, so the full path is
/// <c>/api/v1/sample/notes</c>.
/// </summary>
public static class SampleEndpoints
{
    public static IEndpointRouteBuilder MapSampleEndpoints(this IEndpointRouteBuilder versionedGroup)
    {
        ArgumentNullException.ThrowIfNull(versionedGroup);

        // Owner-scoped module: every route requires an authenticated caller,
        // and reads/deletes then authorize against the note's owner. This is
        // the pattern to copy for a real module's write and read gates.
        var notes = versionedGroup.MapGroup("/sample/notes");

        notes.MapPost("/", CreateNoteAsync).RequireAuthorization();
        notes.MapGet("/{id:guid}", GetNoteByIdAsync).RequireAuthorization();
        notes.MapDelete("/{id:guid}", DeleteNoteAsync).RequireAuthorization();

        return versionedGroup;
    }

    private static async Task<IResult> CreateNoteAsync(
        CreateNoteRequest request,
        ISampleApi sample,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // RequireAuthorization already gates this route; fail closed if a
        // token somehow lacks a parseable sub. The owner of the new note is
        // the authenticated caller.
        var ownerUserId = http.User.GetUserId();
        if (ownerUserId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

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

        var result = await sample.CreateNoteAsync(
            ownerUserId.Value, request.Title!, request.Body!, cancellationToken);
        return result.Match(
            id => Results.Created($"/api/v1/sample/notes/{id}", new CreateNoteResponse(id)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> GetNoteByIdAsync(
        Guid id,
        ISampleApi sample,
        IAuthorizationService authorization,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var lookup = await sample.GetNoteAsync(id, cancellationToken);
        if (lookup.IsFailure)
        {
            // NotFound -> 404 (never 403 for a missing row).
            return lookup.Error.ToProblemResult(http);
        }

        var note = lookup.Value;
        var authorized = await authorization.AuthorizeAsync(
            http.User, new OwnedResource(note.OwnerUserId), ResourceOperations.Read);
        if (!authorized.Succeeded)
        {
            // A non-owner gets 403. An existence-sensitive resource would
            // instead return 404 here, to avoid confirming that the row
            // exists; a note is not sensitive, so 403 is the honest answer.
            return TypedResults.Problem(StarterProblems.ForStatus(http, StatusCodes.Status403Forbidden));
        }

        return Results.Ok(new NoteResponse(note.Id, note.Title, note.Body, note.CreatedAt, note.UpdatedAt));
    }

    private static async Task<IResult> DeleteNoteAsync(
        Guid id,
        ISampleApi sample,
        IAuthorizationService authorization,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var lookup = await sample.GetNoteAsync(id, cancellationToken);
        if (lookup.IsFailure)
        {
            return lookup.Error.ToProblemResult(http);
        }

        var authorized = await authorization.AuthorizeAsync(
            http.User, new OwnedResource(lookup.Value.OwnerUserId), ResourceOperations.Delete);
        if (!authorized.Succeeded)
        {
            // Same 403-vs-404 reasoning as the read above.
            return TypedResults.Problem(StarterProblems.ForStatus(http, StatusCodes.Status403Forbidden));
        }

        var result = await sample.DeleteNoteAsync(id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => error.ToProblemResult(http));
    }
}

/// <summary>POST /api/v1/sample/notes body.</summary>
public sealed record CreateNoteRequest(string? Title, string? Body);

/// <summary>POST /api/v1/sample/notes success: the new note's id.</summary>
public sealed record CreateNoteResponse(Guid Id);

/// <summary>GET /api/v1/sample/notes/{id} success.</summary>
public sealed record NoteResponse(Guid Id, string Title, string Body, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);
