using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The verify-to-write gate on the Sample mutations. An authenticated but
/// UNVERIFIED caller cannot create a note - the `vrf` gate answers 403 with the
/// starter:verification-required problem so the UI can render the reason inline
/// - while a verified caller creates normally. Login itself does not require a
/// verified email (an unverified account can sign in), so this proves the gate
/// is what blocks the write, not the login. Each create carries a valid
/// Idempotency-Key so the outermost idempotency filter passes the request
/// through to the gate rather than short-circuiting on a missing key.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class VerifiedEmailWriteGateTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-6e3d";

    // The tenant-scoped Sample create needs an active tenant. It is supplied so
    // the request reaches the verified-email gate (the subject here), rather
    // than short-circuiting on a missing tenant.
    private readonly Guid _tenant = Guid.CreateVersion7();

    [Fact]
    public async Task UnverifiedCaller_CreateNote_Is403VerificationRequired()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await RegisterAndLoginUnverifiedAsync(
            $"unverified-{Guid.NewGuid():N}@starter.example", cancellationToken);

        var response = await CreateNoteAsync(token, cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:verification-required");
    }

    [Fact]
    public async Task VerifiedCaller_CreateNote_Is201()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"verified-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        var response = await CreateNoteAsync(token, cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    /// <summary>
    /// Register then log in WITHOUT verifying the email: the account exists and
    /// can authenticate, but its address is unproven, so the `vrf` gate blocks
    /// its writes.
    /// </summary>
    private async Task<string> RegisterAndLoginUnverifiedAsync(string email, CancellationToken cancellationToken)
    {
        var register = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/register", new { email, password = Password }, cancellationToken);
        register.EnsureSuccessStatusCode();

        var login = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = Password }, cancellationToken);
        login.EnsureSuccessStatusCode();

        using var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()
            ?? throw new InvalidOperationException("Login returned no access token.");
    }

    private async Task<HttpResponseMessage> CreateNoteAsync(string token, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sample/notes")
        {
            Content = JsonContent.Create(new { title = "Gate probe", body = "verify to write" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("X-Tenant", _tenant.ToString());
        request.Headers.Add("Idempotency-Key", Guid.CreateVersion7().ToString());

        return await fixture.Client.SendAsync(request, cancellationToken);
    }
}
