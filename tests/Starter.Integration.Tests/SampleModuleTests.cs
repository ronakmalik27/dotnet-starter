using System.Net;
using System.Net.Http.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The Sample module over HTTP: create, read, the not-found and validation
/// error shapes, and the transactional-outbox guarantee - the
/// sample.note.created row lands on platform.domain_events in the same
/// transaction as the note.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SampleModuleTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task Create_Get_NotFound_Validation_AndDomainEventLands()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // Create: 201 with the new id.
        var create = await fixture.Client.PostAsJsonAsync(
            "/api/v1/sample/notes",
            new { title = "Trip ideas", body = "Lisbon in spring" },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);

        Guid noteId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            noteId = doc.RootElement.GetProperty("id").GetGuid();
        }

        noteId.ShouldNotBe(Guid.Empty);

        // Get by id: 200 with the stored note.
        var get = await fixture.Client.GetAsync($"/api/v1/sample/notes/{noteId}", cancellationToken);
        get.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(get, cancellationToken))
        {
            doc.RootElement.GetProperty("id").GetGuid().ShouldBe(noteId);
            doc.RootElement.GetProperty("title").GetString().ShouldBe("Trip ideas");
        }

        // Unknown id: 404.
        var missing = await fixture.Client.GetAsync(
            $"/api/v1/sample/notes/{Guid.NewGuid()}", cancellationToken);
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // Empty body: 422 (the validation problem envelope).
        var invalid = await fixture.Client.PostAsJsonAsync(
            "/api/v1/sample/notes",
            new { title = "", body = "" },
            cancellationToken);
        invalid.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // The domain event landed on the append-only spine.
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select count(*) from platform.domain_events "
            + "where event_type = 'sample.note.created' and entity_id = @id",
            connection);
        command.Parameters.AddWithValue("id", noteId);

        var count = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
        count.ShouldBe(1);
    }
}
