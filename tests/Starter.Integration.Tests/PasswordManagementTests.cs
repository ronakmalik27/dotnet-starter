using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Notifications;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The password change and reset flows end to end: an authenticated caller
/// changes a known password (old stops working, new works, a wrong current
/// password is rejected), and the enumeration-safe forgot/reset pair mints a
/// reset token by email, resets the password, and refuses an unknown or
/// reused token - while forgot-password answers identically for a
/// non-existent account and sends it no mail.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class PasswordManagementTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task ChangePassword_WithCorrectCurrentPassword_RotatesCredential()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"change-{Guid.NewGuid():N}@starter.example";
        const string oldPassword = "Starter-Change-Old-Passphrase-1a";
        const string newPassword = "Starter-Change-New-Passphrase-2b";

        var token = await fixture.RegisterVerifyLoginAsync(email, oldPassword, cancellationToken);

        // Wrong current password: 422, the generic validation envelope (no
        // "wrong password" vs "no password" distinction).
        var wrong = await SendAsync(
            HttpMethod.Put, "/api/v1/auth/password", token,
            new { currentPassword = "Starter-Change-Wrong-Passphrase-9z", newPassword },
            cancellationToken);
        wrong.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // Correct current password: 204.
        var change = await SendAsync(
            HttpMethod.Put, "/api/v1/auth/password", token,
            new { currentPassword = oldPassword, newPassword },
            cancellationToken);
        change.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The new password logs in; the old one no longer does.
        var loginNew = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = newPassword }, cancellationToken);
        loginNew.StatusCode.ShouldBe(HttpStatusCode.OK);

        var loginOld = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = oldPassword }, cancellationToken);
        loginOld.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ForgotThenReset_SetsANewPasswordFromTheEmailedToken()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"reset-{Guid.NewGuid():N}@starter.example";
        const string oldPassword = "Starter-Reset-Old-Passphrase-3c";
        const string newPassword = "Starter-Reset-New-Passphrase-4d";

        await fixture.RegisterVerifyLoginAsync(email, oldPassword, cancellationToken);

        // Forgot: 202, and a reset email lands with a token in the link.
        var forgot = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password", new { email }, cancellationToken);
        forgot.StatusCode.ShouldBe(HttpStatusCode.Accepted);

        var resetEmail = await WaitForEmailAsync(email, "Reset your password", cancellationToken);
        var resetToken = HttpTestHelpers.ExtractVerificationToken(resetEmail);
        resetToken.ShouldNotBeNullOrWhiteSpace();

        // Reset with the token + a new password: 204.
        var reset = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/reset-password", new { token = resetToken, newPassword }, cancellationToken);
        reset.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The new password logs in; the old one no longer does.
        var loginNew = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = newPassword }, cancellationToken);
        loginNew.StatusCode.ShouldBe(HttpStatusCode.OK);

        var loginOld = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = oldPassword }, cancellationToken);
        loginOld.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        // Reusing the consumed token: the single-use guard rejects it with
        // the same generic failure as an unknown token.
        var reuse = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new { token = resetToken, newPassword = "Starter-Reset-Another-Passphrase-5e" },
            cancellationToken);
        reuse.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task ForgotPassword_UnknownEmail_Returns202AndSendsNoMail()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var unknown = $"nobody-{Guid.NewGuid():N}@starter.example";

        // The same 202 a real account gets - no enumeration signal.
        var forgot = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/forgot-password", new { email = unknown }, cancellationToken);
        forgot.StatusCode.ShouldBe(HttpStatusCode.Accepted);

        // No account existed, so nothing was mailed to that address. The
        // dispatch is synchronous (inside the request), so this is settled
        // by the time the 202 returns.
        fixture.Emails.Sent.ShouldNotContain(message => message.To == unknown);
    }

    [Fact]
    public async Task ResetPassword_WithUnknownToken_IsAGenericFailure()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var reset = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/reset-password",
            new { token = "this-is-not-a-real-reset-token", newPassword = "Starter-Reset-Bogus-Passphrase-6f" },
            cancellationToken);
        reset.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    private async Task<EmailMessage> WaitForEmailAsync(string to, string subject, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(20);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var match = fixture.Emails.Sent.LastOrDefault(
                message => message.To == to && message.Subject == subject);
            if (match is not null)
            {
                return match;
            }

            await Task.Delay(100, cancellationToken);
        }

        throw new InvalidOperationException($"No '{subject}' email to {to} arrived within the deadline.");
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
