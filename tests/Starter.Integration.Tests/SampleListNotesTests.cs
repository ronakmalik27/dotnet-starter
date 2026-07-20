using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The Sample module's owner-scoped, keyset-paginated list over HTTP: a small
/// page walks the whole set newest-first with no dupes, no gaps, and a null
/// nextCursor on the last page; a second user never sees the first owner's
/// notes (the owner filter is intrinsic to the query); a malformed cursor is a
/// clean 422, not a 500. This is the worked example of the cursor-pagination
/// convention end to end.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SampleListNotesTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-9d2e";

    [Fact]
    public async Task List_KeysetPaginates_OwnerScoped_NewestFirst()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var ownerToken = await fixture.RegisterVerifyLoginAsync(
            $"list-owner-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var strangerToken = await fixture.RegisterVerifyLoginAsync(
            $"list-stranger-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        // Seven notes for the owner, one for the stranger. The owner's list
        // must recover exactly its seven and never the stranger's.
        const int noteCount = 7;
        var ownerNoteIds = new List<Guid>();
        for (var i = 0; i < noteCount; i++)
        {
            ownerNoteIds.Add(await CreateNoteAsync(
                ownerToken, $"Owner note {i}", $"Body {i}", cancellationToken));
        }

        var strangerNoteId = await CreateNoteAsync(
            strangerToken, "Stranger note", "Not yours", cancellationToken);

        // Walk the owner's list a page at a time (limit 3 -> pages of 3, 3, 1).
        var pageSizes = new List<int>();
        var walked = new List<(Guid Id, DateTimeOffset CreatedAt)>();
        string? cursor = null;
        do
        {
            var url = "/api/v1/sample/notes?limit=3"
                + (cursor is null ? string.Empty : $"&cursor={Uri.EscapeDataString(cursor)}");
            var response = await SendAsync(HttpMethod.Get, url, ownerToken, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);

            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            var items = doc.RootElement.GetProperty("items");
            pageSizes.Add(items.GetArrayLength());
            foreach (var item in items.EnumerateArray())
            {
                walked.Add((
                    item.GetProperty("id").GetGuid(),
                    item.GetProperty("createdAt").GetDateTimeOffset()));
            }

            var next = doc.RootElement.GetProperty("nextCursor");
            cursor = next.ValueKind == JsonValueKind.Null ? null : next.GetString();
        }
        while (cursor is not null);

        // Page sizes: 3 + 3 + 1, and the walk terminated (cursor went null).
        pageSizes.ShouldBe([3, 3, 1]);

        // No dupes, no gaps: exactly the owner's seven, never the stranger's.
        var walkedIds = walked.Select(row => row.Id).ToList();
        walkedIds.Count.ShouldBe(noteCount);
        walkedIds.ShouldBeUnique();
        walkedIds.ShouldBe(ownerNoteIds, ignoreOrder: true);
        walkedIds.ShouldNotContain(strangerNoteId);

        // Newest-first: CreatedAt is non-increasing across the whole walk.
        for (var i = 1; i < walked.Count; i++)
        {
            walked[i].CreatedAt.ShouldBeLessThanOrEqualTo(walked[i - 1].CreatedAt);
        }
    }

    [Fact]
    public async Task List_SecondUser_SeesOnlyTheirOwnNotes()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var ownerToken = await fixture.RegisterVerifyLoginAsync(
            $"iso-owner-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var strangerToken = await fixture.RegisterVerifyLoginAsync(
            $"iso-stranger-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        await CreateNoteAsync(ownerToken, "Owner only", "Secret", cancellationToken);
        await CreateNoteAsync(ownerToken, "Owner only 2", "Secret 2", cancellationToken);
        var strangerNoteId = await CreateNoteAsync(
            strangerToken, "Stranger only", "Mine", cancellationToken);

        var response = await SendAsync(
            HttpMethod.Get, "/api/v1/sample/notes", strangerToken, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        var ids = doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid())
            .ToList();

        // The stranger sees exactly their one note and none of the owner's.
        ids.ShouldBe([strangerNoteId]);
    }

    [Fact]
    public async Task List_MalformedCursor_Is422()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var token = await fixture.RegisterVerifyLoginAsync(
            $"cursor-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        var response = await SendAsync(
            HttpMethod.Get, "/api/v1/sample/notes?cursor=not-a-real-cursor", token, cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    private async Task<Guid> CreateNoteAsync(
        string token, string title, string body, CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            HttpMethod.Post, "/api/v1/sample/notes", token, new { title, body }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);

        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string uri, string token, CancellationToken cancellationToken) =>
        SendAsync(method, uri, token, body: null, cancellationToken);

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string uri,
        string token,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await fixture.Client.SendAsync(request, cancellationToken);
    }
}
