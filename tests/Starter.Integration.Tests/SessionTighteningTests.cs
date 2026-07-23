using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Tenant session tightening (role-templates-and-policy-defaults.md section 5),
/// driven through the real endpoints. Proves: an override at or below the platform
/// access-token lifetime is accepted and shortens the tid token; an override longer
/// than the platform lifetime is rejected; a tenant with no override inherits the
/// platform lifetime; and a tightening set after a token was issued is seen on the
/// very next refresh (the mint re-resolves the CURRENT override per rotation).
/// <para>
/// The platform default access-token lifetime is 900 seconds (the seeded constant),
/// so an override below it is the tighter, accepted case and a value above it is the
/// rejected one.
/// </para>
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class SessionTighteningTests(StarterAppFixture fixture)
{
    private const int PlatformAccessLifetime = 900;

    [Fact]
    public async Task OverrideAtOrBelowPlatform_IsAccepted_AndShortensTheTidToken()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Tighten the tenant's session to 120s (<= the 900s platform lifetime).
        var patch = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/tenant", owner.Token, new { sessionMaxSeconds = 120 }, cancellationToken);
        patch.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // A freshly minted tid token now carries min(900, 120) = 120s, reported as
        // exactly the lifetime the token carries.
        (await MintTidExpiresInAsync(owner.TenantId, owner.Token, cancellationToken)).ShouldBe(120);
    }

    [Fact]
    public async Task OverrideLongerThanPlatform_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Loosening (a longer lifetime than the platform floor) is refused: a tenant
        // may only tighten.
        var patch = await TenantWorkflow.PatchJsonAsync(
            fixture,
            "/api/v1/tenant",
            owner.Token,
            new { sessionMaxSeconds = PlatformAccessLifetime + 1 },
            cancellationToken);
        patch.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task NoOverride_InheritsThePlatformLifetime()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // No override set: the tid token inherits the full platform lifetime.
        (await MintTidExpiresInAsync(owner.TenantId, owner.Token, cancellationToken)).ShouldBe(PlatformAccessLifetime);
    }

    [Fact]
    public async Task Tightening_IsSeenOnTheNextRefresh()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("session-refresh");
        var slug = TenantWorkflow.FreshSlug();

        // Sign up (auto-login binds the new tenant), capturing the tid token AND the
        // refresh cookie - the session is tenant-bound, so its refreshes carry the tid.
        var signup = await fixture.Client.PostAsJsonAsync(
            "/api/v1/signup",
            new { email, password = TenantWorkflow.Password, tenantName = "Acme", slug },
            cancellationToken);
        signup.StatusCode.ShouldBe(HttpStatusCode.Created);
        string token;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(signup, cancellationToken))
        {
            token = doc.RootElement.GetProperty("accessToken").GetString()!;
        }

        var refreshCookie = HttpTestHelpers.ReadSetCookie(signup, "starter_refresh");
        refreshCookie.ShouldNotBeNullOrWhiteSpace();
        await TenantWorkflow.VerifyEmailAsync(fixture, email, cancellationToken);

        // Tighten the session AFTER the token was issued.
        var patch = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/tenant", token, new { sessionMaxSeconds = 90 }, cancellationToken);
        patch.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The very next refresh re-resolves the CURRENT override and shortens the
        // rotated tid token to 90s.
        using var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        refreshRequest.Headers.Add("X-Starter-Refresh", "1");
        refreshRequest.Headers.Add("Cookie", $"starter_refresh={refreshCookie}");
        var refresh = await fixture.Client.SendAsync(refreshRequest, cancellationToken);
        refresh.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var refreshDoc = await HttpTestHelpers.ReadJsonAsync(refresh, cancellationToken);
        refreshDoc.RootElement.GetProperty("expiresIn").GetInt32().ShouldBe(90);
    }

    private async Task<int> MintTidExpiresInAsync(Guid tenantId, string bearer, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenants/{tenantId}/token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        var response = await fixture.Client.SendAsync(request, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("expiresIn").GetInt32();
    }
}
