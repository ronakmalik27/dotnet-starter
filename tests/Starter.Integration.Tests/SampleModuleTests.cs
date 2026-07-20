using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The Sample module over HTTP as an authenticated, owner-scoped resource:
/// create sets the caller as owner, the owner can read and delete, a
/// different authenticated user is forbidden (403), a missing row is 404, an
/// empty body is 422, an unauthenticated create is 401 - and the
/// sample.note.created row still lands on platform.domain_events in the same
/// transaction as the note.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SampleModuleTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-9d2e";

    [Fact]
    public async Task OwnerScopedNotes_CreateReadDelete_WithAuthorizationAndDomainEvent()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var ownerToken = await fixture.RegisterVerifyLoginAsync(
            $"owner-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var otherToken = await fixture.RegisterVerifyLoginAsync(
            $"other-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var ownerId = HttpTestHelpers.ReadSubject(ownerToken);

        // Unauthenticated create: 401 (the route now requires authentication).
        var anonymous = await SendAsync(
            HttpMethod.Post, "/api/v1/sample/notes", token: null,
            new { title = "Trip ideas", body = "Lisbon in spring" }, cancellationToken);
        anonymous.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Owner create: 201 with the new id.
        var create = await SendAsync(
            HttpMethod.Post, "/api/v1/sample/notes", ownerToken,
            new { title = "Trip ideas", body = "Lisbon in spring" }, cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);

        Guid noteId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            noteId = doc.RootElement.GetProperty("id").GetGuid();
        }

        noteId.ShouldNotBe(Guid.Empty);

        // Create set the owner: the persisted owner_user_id is the caller.
        await using (var connection = await fixture.OpenConnectionAsync(cancellationToken))
        await using (var ownerQuery = new NpgsqlCommand(
            "select owner_user_id from sample.notes where id = @id", connection))
        {
            ownerQuery.Parameters.AddWithValue("id", noteId);
            var storedOwner = (Guid)(await ownerQuery.ExecuteScalarAsync(cancellationToken))!;
            storedOwner.ShouldBe(ownerId);
        }

        // Owner GET: 200 with the stored note.
        var ownerGet = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{noteId}", ownerToken, body: null, cancellationToken);
        ownerGet.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(ownerGet, cancellationToken))
        {
            doc.RootElement.GetProperty("id").GetGuid().ShouldBe(noteId);
            doc.RootElement.GetProperty("title").GetString().ShouldBe("Trip ideas");
        }

        // A different authenticated user GET: 403 (not the owner).
        var strangerGet = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{noteId}", otherToken, body: null, cancellationToken);
        strangerGet.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // Unknown id (authenticated): 404.
        var missing = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{Guid.NewGuid()}", ownerToken, body: null, cancellationToken);
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // Empty body (authenticated): 422 (the validation problem envelope).
        var invalid = await SendAsync(
            HttpMethod.Post, "/api/v1/sample/notes", ownerToken,
            new { title = "", body = "" }, cancellationToken);
        invalid.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // Non-owner DELETE: 403 (the note still exists afterwards).
        var strangerDelete = await SendAsync(
            HttpMethod.Delete, $"/api/v1/sample/notes/{noteId}", otherToken, body: null, cancellationToken);
        strangerDelete.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // Owner DELETE: 204 No Content.
        var ownerDelete = await SendAsync(
            HttpMethod.Delete, $"/api/v1/sample/notes/{noteId}", ownerToken, body: null, cancellationToken);
        ownerDelete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // GET after delete: 404.
        var afterDelete = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{noteId}", ownerToken, body: null, cancellationToken);
        afterDelete.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // The domain event landed on the append-only spine when the note was
        // created (delete emits none).
        await using var eventConnection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select count(*) from platform.domain_events "
            + "where event_type = 'sample.note.created' and entity_id = @id",
            eventConnection);
        command.Parameters.AddWithValue("id", noteId);

        var count = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
        count.ShouldBe(1);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string uri,
        string? token,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await fixture.Client.SendAsync(request, cancellationToken);
    }
}
