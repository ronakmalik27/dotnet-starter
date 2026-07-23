using System.Net;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Platform policy defaults (role-templates-and-policy-defaults.md section 3),
/// driven through the real super-admin endpoints. Proves: raising
/// password_min_length changes what a new password must satisfy; changing the
/// access-token lifetime changes the issued token's reported expiry (which equals
/// the exp it carries); out-of-bounds values are rejected; and a non-super-admin is
/// refused the catalogue.
/// <para>
/// The policy-defaults row is a global singleton the integration collection shares,
/// so every test that mutates it RESTORES the built-in value in a finally (the
/// update path invalidates the in-process cache, so the restore is seen at once) -
/// otherwise a raised floor would leak into every later test.
/// </para>
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class PolicyDefaultsTests(StarterAppFixture fixture)
{
    // The seeded built-in constants, restored after each mutation.
    private const int DefaultPasswordMinLength = 10;
    private const int DefaultAccessTokenLifetimeSeconds = 900;

    [Fact]
    public async Task UpdatingPasswordMinLength_ChangesWhatANewPasswordMustSatisfy()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        try
        {
            // Raise the platform minimum to 12.
            var raise = await TenantWorkflow.PatchJsonAsync(
                fixture, "/api/v1/platform/policy-defaults", admin.Token, new { passwordMinLength = 12 }, cancellationToken);
            raise.StatusCode.ShouldBe(HttpStatusCode.NoContent);

            // The GET reflects the change.
            var read = await PlatformWorkflow.GetAsync(fixture, "/api/v1/platform/policy-defaults", admin.Token, cancellationToken);
            read.StatusCode.ShouldBe(HttpStatusCode.OK);
            using (var doc = await HttpTestHelpers.ReadJsonAsync(read, cancellationToken))
            {
                doc.RootElement.GetProperty("passwordMinLength").GetInt32().ShouldBe(12);
            }

            // An 11-char (non-breached) password is now rejected where the built-in 10
            // would have accepted it.
            var tooShort = await fixture.Client.PostAsJsonAsync(
                "/api/v1/auth/register",
                new { email = TenantWorkflow.FreshEmail("policy-min"), password = "kZ2!vq81#La" },
                cancellationToken);
            tooShort.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

            // A 12-char password satisfies the raised floor.
            var longEnough = await fixture.Client.PostAsJsonAsync(
                "/api/v1/auth/register",
                new { email = TenantWorkflow.FreshEmail("policy-min"), password = "kZ2!vq81#Ls0" },
                cancellationToken);
            longEnough.StatusCode.ShouldBe(HttpStatusCode.OK);
        }
        finally
        {
            await RestorePasswordMinLengthAsync(admin.Token, cancellationToken);
        }
    }

    [Fact]
    public async Task UpdatingAccessTokenLifetime_ChangesTheIssuedTokenExpiry()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var email = TenantWorkflow.FreshEmail("policy-ttl");
        await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);

        try
        {
            // Shorten the platform access-token lifetime to 120 seconds.
            var shorten = await TenantWorkflow.PatchJsonAsync(
                fixture,
                "/api/v1/platform/policy-defaults",
                admin.Token,
                new { accessTokenLifetimeSeconds = 120 },
                cancellationToken);
            shorten.StatusCode.ShouldBe(HttpStatusCode.NoContent);

            // A fresh login reports the new lifetime, which is exactly what the token
            // carries (the mint returns the resolved lifetime).
            var login = await fixture.Client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TenantWorkflow.Password }, cancellationToken);
            login.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken);
            doc.RootElement.GetProperty("expiresIn").GetInt32().ShouldBe(120);
        }
        finally
        {
            var restore = await TenantWorkflow.PatchJsonAsync(
                fixture,
                "/api/v1/platform/policy-defaults",
                admin.Token,
                new { accessTokenLifetimeSeconds = DefaultAccessTokenLifetimeSeconds },
                cancellationToken);
            restore.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        }
    }

    [Fact]
    public async Task UpdatePolicyDefaults_RejectsOutOfBounds()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // A zero minimum length is out of bounds (must be positive); nothing changes.
        var rejected = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/platform/policy-defaults", admin.Token, new { passwordMinLength = 0 }, cancellationToken);
        rejected.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // The floor is unchanged (still the built-in 10).
        var read = await PlatformWorkflow.GetAsync(fixture, "/api/v1/platform/policy-defaults", admin.Token, cancellationToken);
        using var doc = await HttpTestHelpers.ReadJsonAsync(read, cancellationToken);
        doc.RootElement.GetProperty("passwordMinLength").GetInt32().ShouldBe(DefaultPasswordMinLength);
    }

    [Fact]
    public async Task PolicyDefaults_NonSuperAdmin_Refused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var read = await PlatformWorkflow.GetAsync(fixture, "/api/v1/platform/policy-defaults", owner.Token, cancellationToken);
        read.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        var write = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/platform/policy-defaults", owner.Token, new { passwordMinLength = 8 }, cancellationToken);
        write.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    private async Task RestorePasswordMinLengthAsync(string adminToken, CancellationToken cancellationToken)
    {
        var restore = await TenantWorkflow.PatchJsonAsync(
            fixture,
            "/api/v1/platform/policy-defaults",
            adminToken,
            new { passwordMinLength = DefaultPasswordMinLength },
            cancellationToken);
        restore.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }
}
