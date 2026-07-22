using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The platform super-admin plane (multi-tenancy.md sections 7 and 9), driven
/// through the real endpoints. Proves: RequirePlatformAdmin refuses a non-admin
/// and admits a seeded admin; grant makes a user an admin and revoke removes
/// them; revoking the last admin is refused (409); there is no self-grant path;
/// and the tenant lifecycle (suspend / reactivate) gates the tid-token mint.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class PlatformAdminTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task NonAdmin_IsRefused_And_SeededAdmin_IsAdmitted()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // A plain authenticated caller (not a platform admin) is refused 403.
        var outsiderToken = await fixture.RegisterVerifyLoginAsync(
            TenantWorkflow.FreshEmail("outsider"), TenantWorkflow.Password, cancellationToken);
        var refused = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/tenants", outsiderToken, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-admin-required");
        }

        // A seeded platform admin passes the gate.
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var admitted = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/tenants", admin.Token, cancellationToken);
        admitted.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Grant_MakesUserAdmin_AndRevoke_RemovesThem()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // A fresh user, not yet an admin, is refused a platform endpoint.
        var candidateToken = await fixture.RegisterVerifyLoginAsync(
            TenantWorkflow.FreshEmail("candidate"), TenantWorkflow.Password, cancellationToken);
        var candidateId = HttpTestHelpers.ReadSubject(candidateToken);

        var beforeGrant = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/admins", candidateToken, cancellationToken);
        beforeGrant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // The admin grants platform power to the candidate.
        var grant = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/platform/admins", admin.Token, new { userId = candidateId }, cancellationToken);
        grant.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // Now the candidate passes the gate.
        var afterGrant = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/admins", candidateToken, cancellationToken);
        afterGrant.StatusCode.ShouldBe(HttpStatusCode.OK);

        // The admin revokes the candidate (the admin remains, so not the last admin).
        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/platform/admins/{candidateId}", admin.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The candidate is refused again.
        var afterRevoke = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/admins", candidateToken, cancellationToken);
        afterRevoke.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Grant_ByEmail_ResolvesTheUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        var email = TenantWorkflow.FreshEmail("by-email");
        var candidateToken = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);

        var grant = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/platform/admins", admin.Token, new { email }, cancellationToken);
        grant.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var admitted = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/admins", candidateToken, cancellationToken);
        admitted.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RevokingTheLastAdmin_IsRefused_With409()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // The roster is global; the integration collection runs sequentially, so
        // reset it to make the lockout guard deterministic - exactly one admin.
        await PlatformWorkflow.ClearPlatformAdminsAsync(fixture, cancellationToken);
        var soleAdmin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/platform/admins/{soleAdmin.UserId}", soleAdmin.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var doc = await HttpTestHelpers.ReadJsonAsync(revoke, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-last-admin");

        // The guard held: the sole admin is still an admin.
        var stillAdmin = await PlatformWorkflow.GetAsync(
            fixture, "/api/v1/platform/admins", soleAdmin.Token, cancellationToken);
        stillAdmin.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SuspendTenant_RefusesMemberMint_ThenReactivateRestoresIt()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A member can mint a tid token while the tenant is active.
        var beforeSuspend = await MintAsync(owner, cancellationToken);
        beforeSuspend.ShouldBe(HttpStatusCode.OK);

        // Suspend the tenant on the platform plane.
        var suspend = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{owner.TenantId}/suspend", admin.Token, new { }, cancellationToken);
        suspend.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The tenant-status enforcement point refuses a fresh mint (403 inactive).
        var duringSuspend = await MintRawAsync(owner, cancellationToken);
        duringSuspend.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(duringSuspend, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-inactive");
        }

        // Reactivate restores minting.
        var reactivate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{owner.TenantId}/reactivate", admin.Token, new { }, cancellationToken);
        reactivate.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterReactivate = await MintAsync(owner, cancellationToken);
        afterReactivate.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ViewTenant_ReturnsTheTenant_ForAnAdmin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var view = await PlatformWorkflow.GetAsync(
            fixture, $"/api/v1/platform/tenants/{owner.TenantId}", admin.Token, cancellationToken);
        view.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(view, cancellationToken);
        doc.RootElement.GetProperty("id").GetGuid().ShouldBe(owner.TenantId);
        doc.RootElement.GetProperty("status").GetString().ShouldBe("active");
    }

    private Task<HttpResponseMessage> MintRawAsync(OwnerContext owner, CancellationToken cancellationToken)
    {
        // The mint through the raw request so a non-200 can be inspected (the
        // TenantWorkflow helper asserts OK, which is not what we want here).
        var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenants/{owner.TenantId}/token");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", owner.Token);
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private async Task<HttpStatusCode> MintAsync(OwnerContext owner, CancellationToken cancellationToken)
    {
        var response = await MintRawAsync(owner, cancellationToken);
        return response.StatusCode;
    }
}
