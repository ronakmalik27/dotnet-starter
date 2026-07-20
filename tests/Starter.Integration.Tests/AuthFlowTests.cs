using System.Net;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The full password auth round-trip end to end, and the email side of it:
/// register issues a verification email (captured by the fake transport),
/// its token verifies the address, login returns an access token and sets
/// the refresh cookie, and refresh trades the cookie for a fresh access
/// token. This is Features 1 and 2 proven from the outside.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class AuthFlowTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Integration-Passphrase-7c1f";

    [Fact]
    public async Task Register_Verify_Login_Refresh_RoundTrips()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"user-{Guid.NewGuid():N}@starter.example";

        // Register: 200 { registered: true }.
        var register = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/register",
            new { email, password = Password },
            cancellationToken);
        register.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(register, cancellationToken))
        {
            doc.RootElement.GetProperty("registered").GetBoolean().ShouldBeTrue();
        }

        // Exactly one verification email to this address, with a token in the
        // link (the email-capture assertion, Feature 1 + 2).
        var captured = fixture.Emails.Sent.Where(message => message.To == email).ToList();
        captured.ShouldHaveSingleItem();
        var token = HttpTestHelpers.ExtractVerificationToken(captured[0]);
        token.ShouldNotBeNullOrWhiteSpace();

        // Verify: 200 { verified: true }.
        var verify = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/verify-email",
            new { token },
            cancellationToken);
        verify.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(verify, cancellationToken))
        {
            doc.RootElement.GetProperty("verified").GetBoolean().ShouldBeTrue();
        }

        // Login: 200 with an access token and the refresh cookie.
        var login = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new { email, password = Password },
            cancellationToken);
        login.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken))
        {
            doc.RootElement.GetProperty("accessToken").GetString().ShouldNotBeNullOrWhiteSpace();
            doc.RootElement.GetProperty("expiresIn").GetInt32().ShouldBeGreaterThan(0);
        }

        var refreshCookie = HttpTestHelpers.ReadSetCookie(login, "starter_refresh");
        refreshCookie.ShouldNotBeNullOrWhiteSpace();

        // Refresh: 200 with a new access token, given the cookie plus the
        // required companion header.
        using var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        refreshRequest.Headers.Add("X-Starter-Refresh", "1");
        refreshRequest.Headers.Add("Cookie", $"starter_refresh={refreshCookie}");

        var refresh = await fixture.Client.SendAsync(refreshRequest, cancellationToken);
        refresh.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(refresh, cancellationToken))
        {
            doc.RootElement.GetProperty("accessToken").GetString().ShouldNotBeNullOrWhiteSpace();
        }
    }
}
