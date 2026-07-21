using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The load-bearing session-security invariants, proven end to end through the
/// real cookie/refresh flow (the same transport AuthFlowTests exercises):
/// refresh-token rotation with reuse detection kills the whole family, and a
/// token-version bump (from a password change) invalidates every existing
/// session at its next refresh.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SecurityFlowTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Security-Passphrase-8f2c";

    [Fact]
    public async Task RefreshTokenReuse_RevokesTheWholeSessionFamily()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"reuse-{Guid.NewGuid():N}@starter.example";
        var (_, initialRefresh) = await RegisterVerifyLoginWithCookieAsync(email, Password, cancellationToken);

        // Normal rotation: the initial refresh token trades for a new one and
        // is retired.
        var rotate = await RefreshAsync(initialRefresh, cancellationToken);
        rotate.StatusCode.ShouldBe(HttpStatusCode.OK);
        var rotatedRefresh = HttpTestHelpers.ReadSetCookie(rotate, "starter_refresh");
        rotatedRefresh.ShouldNotBeNullOrWhiteSpace();

        // Present the OLD (already-rotated) token again: reuse. It is rejected
        // (401) AND the whole family is revoked as compromised.
        var reuse = await RefreshAsync(initialRefresh, cancellationToken);
        reuse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // The family is dead: the previously-valid rotated token is now 401
        // too, even though it was never itself reused.
        var afterFamilyDead = await RefreshAsync(rotatedRefresh!, cancellationToken);
        afterFamilyDead.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PasswordChangeBumpsVer_InvalidatesExistingSessionAtNextRefresh()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"verbump-{Guid.NewGuid():N}@starter.example";
        const string oldPassword = "Starter-Verbump-Old-Passphrase-1a";
        const string newPassword = "Starter-Verbump-New-Passphrase-2b";
        var (accessToken, refreshCookie) =
            await RegisterVerifyLoginWithCookieAsync(email, oldPassword, cancellationToken);

        // Change the password: this bumps the user's token version, which is
        // enforced at refresh, so every session issued under the old version
        // dies on its next refresh.
        using var change = new HttpRequestMessage(HttpMethod.Put, "/api/v1/auth/password")
        {
            Content = JsonContent.Create(new { currentPassword = oldPassword, newPassword }),
        };
        change.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var changeResponse = await fixture.Client.SendAsync(change, cancellationToken);
        changeResponse.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The pre-existing session carries the old ver: its next refresh is 401.
        var refresh = await RefreshAsync(refreshCookie, cancellationToken);
        refresh.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Register, verify from the captured email, and log in - returning both the
    /// access token and the refresh cookie (RegisterVerifyLoginAsync returns only
    /// the access token, and these tests need the cookie to drive refresh).
    /// </summary>
    private async Task<(string AccessToken, string RefreshCookie)> RegisterVerifyLoginWithCookieAsync(
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var register = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/register", new { email, password }, cancellationToken);
        register.EnsureSuccessStatusCode();

        var verificationEmail = fixture.Emails.Sent.Last(message => message.To == email);
        var verificationToken = HttpTestHelpers.ExtractVerificationToken(verificationEmail);

        var verify = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/verify-email", new { token = verificationToken }, cancellationToken);
        verify.EnsureSuccessStatusCode();

        var login = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password }, cancellationToken);
        login.EnsureSuccessStatusCode();

        var refreshCookie = HttpTestHelpers.ReadSetCookie(login, "starter_refresh")
            ?? throw new InvalidOperationException("Login set no refresh cookie.");
        using var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken);
        var accessToken = doc.RootElement.GetProperty("accessToken").GetString()
            ?? throw new InvalidOperationException("Login returned no access token.");
        return (accessToken, refreshCookie);
    }

    private async Task<HttpResponseMessage> RefreshAsync(string refreshCookie, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("X-Starter-Refresh", "1");
        request.Headers.Add("Cookie", $"starter_refresh={refreshCookie}");
        return await fixture.Client.SendAsync(request, cancellationToken);
    }
}
