using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// Shared HTTP workflow helpers for the tenant RBAC / invitation / admin suites,
/// driving everything through the real endpoints on the fixture: signing up an
/// owner (tenant + owner membership + verified email + a tid-bound token), and
/// inviting + registering + accepting + minting a tid token for a new member.
/// Kept in one place so each suite reads as its assertions, not its plumbing.
/// </summary>
internal static class TenantWorkflow
{
    public const string Password = "Starter-Tenant-Passphrase-9f2a";

    public static string FreshEmail(string tag) => $"{tag}-{Guid.NewGuid():N}@starter.example";

    public static string FreshSlug() => $"tenant-{Guid.NewGuid():N}";

    /// <summary>
    /// Signs up a fresh owner: creates the tenant and owner membership, verifies
    /// the owner's email (so the owner can write), and returns a tid-bound access
    /// token plus the identifiers.
    /// </summary>
    public static async Task<OwnerContext> SignupOwnerAsync(
        StarterAppFixture fixture, CancellationToken cancellationToken)
    {
        var email = FreshEmail("owner");
        var slug = FreshSlug();

        var signup = await fixture.Client.PostAsJsonAsync(
            "/api/v1/signup",
            new { email, password = Password, tenantName = "Acme", slug },
            cancellationToken);
        signup.StatusCode.ShouldBe(HttpStatusCode.Created);

        var token = await ReadAccessTokenAsync(signup, cancellationToken);
        var tenantId = Guid.Parse(HttpTestHelpers.ReadClaim(token, "tid")!);
        var userId = HttpTestHelpers.ReadSubject(token);

        await VerifyEmailAsync(fixture, email, cancellationToken);

        return new OwnerContext(token, tenantId, userId, email);
    }

    /// <summary>
    /// Onboards a fresh member into the owner's tenant end to end: the owner
    /// invites the email with <paramref name="role"/>, a new account registers and
    /// verifies, accepts the emailed invitation, and mints a tid token. Returns
    /// the member's tid-bound token and identifiers.
    /// </summary>
    public static async Task<MemberContext> InviteAcceptMintAsync(
        StarterAppFixture fixture,
        OwnerContext owner,
        string role,
        CancellationToken cancellationToken)
    {
        var email = FreshEmail(role);

        // The invitee's account exists and is verified before the invite, so the
        // later mailbox lookup for the invitation email is unambiguous.
        var inviteeToken = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(inviteeToken);

        var invite = await PostJsonAsync(
            fixture, "/api/v1/tenant/invitations", owner.Token, new { email, role }, cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var invitationEmail = fixture.Emails.Sent.Last(
            message => message.To == email && message.Subject.Contains("invited", StringComparison.Ordinal));
        var rawToken = HttpTestHelpers.ExtractVerificationToken(invitationEmail);

        var accept = await PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
        accept.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tidToken = await MintTenantTokenAsync(fixture, owner.TenantId, inviteeToken, cancellationToken);
        return new MemberContext(tidToken, userId, email);
    }

    public static async Task VerifyEmailAsync(
        StarterAppFixture fixture, string email, CancellationToken cancellationToken)
    {
        var verificationEmail = fixture.Emails.Sent.Last(
            message => message.To == email && message.Subject.Contains("Verify", StringComparison.Ordinal));
        var token = HttpTestHelpers.ExtractVerificationToken(verificationEmail);
        var verify = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/verify-email", new { token }, cancellationToken);
        verify.EnsureSuccessStatusCode();
    }

    public static async Task<string> MintTenantTokenAsync(
        StarterAppFixture fixture, Guid tenantId, string bearer, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenants/{tenantId}/token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        var response = await fixture.Client.SendAsync(request, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()!;
    }

    public static Task<HttpResponseMessage> PostJsonAsync(
        StarterAppFixture fixture, string uri, string bearer, object body, CancellationToken cancellationToken) =>
        SendJsonAsync(fixture, HttpMethod.Post, uri, bearer, body, cancellationToken);

    public static Task<HttpResponseMessage> PatchJsonAsync(
        StarterAppFixture fixture, string uri, string bearer, object body, CancellationToken cancellationToken) =>
        SendJsonAsync(fixture, HttpMethod.Patch, uri, bearer, body, cancellationToken);

    public static Task<HttpResponseMessage> GetAsync(
        StarterAppFixture fixture, string uri, string bearer, CancellationToken cancellationToken) =>
        SendAsync(fixture, HttpMethod.Get, uri, bearer, cancellationToken);

    public static Task<HttpResponseMessage> DeleteAsync(
        StarterAppFixture fixture, string uri, string bearer, CancellationToken cancellationToken) =>
        SendAsync(fixture, HttpMethod.Delete, uri, bearer, cancellationToken);

    public static async Task<HttpResponseMessage> CreateNoteAsync(
        StarterAppFixture fixture, string bearer, string title, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sample/notes");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        request.Headers.Add("Idempotency-Key", Guid.CreateVersion7().ToString());
        request.Content = JsonContent.Create(new { title, body = "body" });
        return await fixture.Client.SendAsync(request, cancellationToken);
    }

    private static Task<HttpResponseMessage> SendJsonAsync(
        StarterAppFixture fixture,
        HttpMethod method,
        string uri,
        string bearer,
        object body,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, uri)
        {
            Content = JsonContent.Create(body),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private static Task<HttpResponseMessage> SendAsync(
        StarterAppFixture fixture,
        HttpMethod method,
        string uri,
        string bearer,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private static async Task<string> ReadAccessTokenAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()!;
    }
}

/// <summary>An onboarded owner: a tid-bound token plus the tenant and user ids and the email.</summary>
internal sealed record OwnerContext(string Token, Guid TenantId, Guid UserId, string Email);

/// <summary>An onboarded member: a tid-bound token plus the user id and the email.</summary>
internal sealed record MemberContext(string Token, Guid UserId, string Email);
