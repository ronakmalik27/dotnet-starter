using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Idempotency at the HTTP boundary, end to end, now that the Sample create is
/// the worked example wired with RequireIdempotency. The same Idempotency-Key
/// sent twice replays the stored 201 (marked Idempotency-Replayed: true) and
/// creates exactly one note - the note, its domain_events row, its outbox rows,
/// and the stored response all committed in the one filter-owned transaction.
/// Two different keys create two notes. A missing or non-UUIDv7 key is rejected
/// by the filter before the handler runs. The caller is verified (the create
/// route also gates on a verified email), so these tests isolate the
/// idempotency behavior.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class IdempotencyTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-4b7a";

    // The tenant-scoped Sample create needs an active tenant (the X-Tenant header).
    private readonly Guid _tenant = Guid.CreateVersion7();

    [Fact]
    public async Task SameKeyTwice_ReplaysStoredResponse_AndCreatesExactlyOneNote()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"idem-replay-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var ownerId = HttpTestHelpers.ReadSubject(token);
        var key = Guid.CreateVersion7().ToString();

        var first = await PostNoteAsync(token, key, cancellationToken);
        var second = await PostNoteAsync(token, key, cancellationToken);

        // First execution: a real 201, not a replay.
        first.Status.ShouldBe(HttpStatusCode.Created);
        first.Replayed.ShouldBeFalse();

        // Second: the stored 201 replayed verbatim, marked as a replay, same id.
        second.Status.ShouldBe(HttpStatusCode.Created);
        second.Replayed.ShouldBeTrue();
        second.Id.ShouldBe(first.Id);

        // Exactly one note exists for this owner: the replay did not act twice.
        (await CountNotesAsync(ownerId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task TwoDifferentKeys_CreateTwoNotes()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"idem-distinct-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var ownerId = HttpTestHelpers.ReadSubject(token);

        var first = await PostNoteAsync(token, Guid.CreateVersion7().ToString(), cancellationToken);
        var second = await PostNoteAsync(token, Guid.CreateVersion7().ToString(), cancellationToken);

        first.Status.ShouldBe(HttpStatusCode.Created);
        second.Status.ShouldBe(HttpStatusCode.Created);
        second.Id.ShouldNotBe(first.Id);
        second.Replayed.ShouldBeFalse();

        (await CountNotesAsync(ownerId, cancellationToken)).ShouldBe(2);
    }

    [Fact]
    public async Task MissingKey_IsRejectedByTheFilter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"idem-missing-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        var response = await PostNoteAsync(token, key: null, cancellationToken);

        // The filter requires the key and rejects with the validation envelope.
        response.Status.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task NonUuidV7Key_IsRejectedByTheFilter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"idem-v4-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        // A UUIDv4 parses as a Guid but fails the filter's UUIDv7 requirement.
        var response = await PostNoteAsync(token, Guid.NewGuid().ToString(), cancellationToken);

        response.Status.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    private async Task<(HttpStatusCode Status, Guid Id, bool Replayed)> PostNoteAsync(
        string token,
        string? key,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sample/notes")
        {
            Content = JsonContent.Create(new { title = "Idempotency probe", body = "worked example" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("X-Tenant", _tenant.ToString());
        if (key is not null)
        {
            request.Headers.Add("Idempotency-Key", key);
        }

        var response = await fixture.Client.SendAsync(request, cancellationToken);
        var replayed = response.Headers.TryGetValues("Idempotency-Replayed", out var values)
            && values.Contains("true");
        if (response.StatusCode != HttpStatusCode.Created)
        {
            return (response.StatusCode, Guid.Empty, replayed);
        }

        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (response.StatusCode, doc.RootElement.GetProperty("id").GetGuid(), replayed);
    }

    private async Task<long> CountNotesAsync(Guid ownerId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select count(*) from sample.notes where owner_user_id = @owner", connection);
        command.Parameters.AddWithValue("owner", ownerId);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
