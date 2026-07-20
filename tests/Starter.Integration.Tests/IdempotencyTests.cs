using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Idempotency at the HTTP boundary. No production endpoint is wired with
/// RequireIdempotency today: the anonymous auth endpoints are naturally
/// retry-safe by design (registration converges on the same success, login
/// re-issues, refresh reuse is detected), and the sample routes - though now
/// authenticated and owner-scoped - still do not opt into the filter. This
/// test pins that documented state: sending the same Idempotency-Key twice to
/// the sample create executes twice and returns two distinct notes, because no
/// endpoint honors the header.
///
/// The filter's own replay/capture/in-flight semantics are covered by the
/// Starter.Platform.Tests unit suite (IdempotentResponseSnapshotTests and
/// the surrounding cases); when an authenticated mutating endpoint later
/// adopts RequireIdempotency, this test is the natural place to add the
/// same-key replay assertion end to end.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class IdempotencyTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-4b7a";

    [Fact]
    public async Task NoIdempotentEndpointWired_DuplicateKeyExecutesTwice()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"idem-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var key = Guid.CreateVersion7().ToString();

        var first = await PostNoteWithKeyAsync(token, key, cancellationToken);
        var second = await PostNoteWithKeyAsync(token, key, cancellationToken);

        first.Status.ShouldBe(HttpStatusCode.Created);
        second.Status.ShouldBe(HttpStatusCode.Created);
        second.Id.ShouldNotBe(first.Id);
    }

    private async Task<(HttpStatusCode Status, Guid Id)> PostNoteWithKeyAsync(
        string token,
        string key,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sample/notes")
        {
            Content = JsonContent.Create(new { title = "Idempotency probe", body = "same key twice" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("Idempotency-Key", key);

        var response = await fixture.Client.SendAsync(request, cancellationToken);
        if (response.StatusCode != HttpStatusCode.Created)
        {
            return (response.StatusCode, Guid.Empty);
        }

        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (response.StatusCode, doc.RootElement.GetProperty("id").GetGuid());
    }
}
