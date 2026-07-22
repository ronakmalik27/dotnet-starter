using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Tenancy;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Self-serve provisioning and the tid token mint (multi-tenancy.md section 8
/// and the increment-2 provisioning tests). Proves: signup creates a user, a
/// tenant, and the owner membership atomically and logs the owner in with a
/// tid-bound token; a failure mid-provisioning leaves neither a user nor a
/// tenant; existing-email signup is enumeration-safe; slug uniqueness is
/// citext/case-insensitive; a member can mint a tid token and a non-member
/// cannot; refresh preserves the selected tenant; and the membership directory
/// answers the mint gate.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TenantProvisioningTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Provisioning-Passphrase-7a3b";

    [Fact]
    public async Task SelfServeSignup_FreshEmail_CreatesTenantOwnerMembership_AndLogsInWithTid()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = FreshEmail();
        var slug = FreshSlug();

        var response = await SignupAsync(email, slug, "Acme Inc", cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);

        var accessToken = await ReadAccessTokenAsync(response, cancellationToken);
        accessToken.ShouldNotBeNullOrEmpty();

        // The auto-login token carries tid = the new tenant.
        var tenantId = Guid.Parse(HttpTestHelpers.ReadClaim(accessToken, "tid")
            ?? throw new InvalidOperationException("The signup token carries no tid."));
        var ownerId = HttpTestHelpers.ReadSubject(accessToken);

        // The persisted control-plane state: exactly one tenant with that slug,
        // owned by the new user, and one active owner membership.
        (await CountAsync(
            "select count(*) from tenancy.tenants where id = @id and slug = @slug and status = 'active' and created_by = @owner",
            cancellationToken, ("id", tenantId), ("slug", slug), ("owner", ownerId)))
            .ShouldBe(1);
        (await CountAsync(
            "select count(*) from tenancy.memberships where tenant_id = @tid and user_id = @owner and role = 'owner' and status = 'active'",
            cancellationToken, ("tid", tenantId), ("owner", ownerId)))
            .ShouldBe(1);

        // The owner can immediately act under that tenant. Verify the emailed
        // address (writes require a verified email), then create and list a note
        // - the tenant resolves from the token's tid, no X-Tenant needed.
        await VerifyEmailForAsync(email, cancellationToken);

        var create = await CreateNoteAsync(accessToken, "First note", cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid noteId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            noteId = doc.RootElement.GetProperty("id").GetGuid();
        }

        (await ListNoteIdsAsync(accessToken, cancellationToken)).ShouldContain(noteId);
    }

    [Fact]
    public async Task SelfServeSignup_Atomicity_SlugCollisionLeavesNeitherUserNorTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var slug = FreshSlug();
        var firstEmail = FreshEmail();
        var secondEmail = FreshEmail();

        // First signup wins the slug.
        (await SignupAsync(firstEmail, slug, "First", cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.Created);

        // Second signup: a DIFFERENT (fresh) email, the SAME slug. The provisioner
        // stages the new user first, then the tenant insert hits the citext slug
        // unique index and the whole unit rolls back. 409, and - the crown-jewel
        // invariant - a failure leaves NEITHER the user NOR the tenant.
        var collision = await SignupAsync(secondEmail, slug, "Second", cancellationToken);
        collision.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(collision, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-slug-taken");
        }

        // The staged user for the failed attempt did not survive the rollback.
        (await CountAsync(
            "select count(*) from identity.users where email = @email", cancellationToken, ("email", secondEmail)))
            .ShouldBe(0);
        // Exactly one tenant holds the slug (the first signup's), so the second
        // created no tenant either.
        (await CountAsync(
            "select count(*) from tenancy.tenants where slug = @slug", cancellationToken, ("slug", slug)))
            .ShouldBe(1);
        // The first signup's user is intact (control: the rollback was scoped to
        // the failed unit, not a blanket wipe).
        (await CountAsync(
            "select count(*) from identity.users where email = @email", cancellationToken, ("email", firstEmail)))
            .ShouldBe(1);
    }

    [Fact]
    public async Task SelfServeSignup_ExistingEmail_IsEnumerationSafe_AndCreatesNoNewTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = FreshEmail();
        var firstSlug = FreshSlug();
        var secondSlug = FreshSlug();

        // First signup establishes the account (and a tenant).
        (await SignupAsync(email, firstSlug, "Original", cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.Created);

        // A second signup with the SAME email but a fresh slug: enumeration-safe.
        // It returns the SAME 201 as a fresh signup and does NOT reveal that the
        // email pre-existed - but it creates no user and no tenant for the second
        // slug.
        var repeat = await SignupAsync(email, secondSlug, "Impostor", cancellationToken);
        repeat.StatusCode.ShouldBe(HttpStatusCode.Created);

        (await CountAsync(
            "select count(*) from tenancy.tenants where slug = @slug", cancellationToken, ("slug", secondSlug)))
            .ShouldBe(0);
        // Still exactly one account for the email (the second attempt created none).
        (await CountAsync(
            "select count(*) from identity.users where email = @email", cancellationToken, ("email", email)))
            .ShouldBe(1);
    }

    [Fact]
    public async Task SelfServeSignup_Slug_IsCaseInsensitive_Collides409()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        // Two slugs that differ ONLY in the case of their leading letters; the
        // shared suffix is lowercase hex, so they are citext-equal.
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var mixedCase = $"Acme{suffix}";
        var lowerCase = $"acme{suffix}";

        (await SignupAsync(FreshEmail(), mixedCase, "Acme", cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.Created);

        // "acme..." collides with "Acme..." in the citext unique index -> 409.
        var collision = await SignupAsync(FreshEmail(), lowerCase, "Acme lower", cancellationToken);
        collision.StatusCode.ShouldBe(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task TenantToken_Member_MintsTidToken_NonMember_Gets404()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // A signup owner is a member of the new tenant.
        var ownerSignup = await SignupAsync(FreshEmail(), FreshSlug(), "Owner Co", cancellationToken);
        ownerSignup.StatusCode.ShouldBe(HttpStatusCode.Created);
        var ownerToken = await ReadAccessTokenAsync(ownerSignup, cancellationToken);
        var tenantId = Guid.Parse(HttpTestHelpers.ReadClaim(ownerToken, "tid")!);

        // The member mints a tenant token: 200, carrying tid for that tenant.
        var mint = await MintTenantTokenAsync(tenantId, ownerToken, cancellationToken);
        mint.StatusCode.ShouldBe(HttpStatusCode.OK);
        string mintedToken;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(mint, cancellationToken))
        {
            mintedToken = doc.RootElement.GetProperty("accessToken").GetString()!;
        }

        HttpTestHelpers.ReadClaim(mintedToken, "tid").ShouldBe(tenantId.ToString());

        // A different, verified, logged-in user who is NOT a member gets 404 -
        // never confirming the tenant exists.
        var strangerToken = await fixture.RegisterVerifyLoginAsync(FreshEmail(), Password, cancellationToken);
        var strangerMint = await MintTenantTokenAsync(tenantId, strangerToken, cancellationToken);
        strangerMint.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(strangerMint, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-membership-not-found");
        }
    }

    [Fact]
    public async Task Refresh_PreservesTheSelectedTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = FreshEmail();

        // Signup makes the owner a member of a tenant; capture the tenant id.
        var signup = await SignupAsync(email, FreshSlug(), "Refresh Co", cancellationToken);
        signup.StatusCode.ShouldBe(HttpStatusCode.Created);
        var tenantId = Guid.Parse(HttpTestHelpers.ReadClaim(
            await ReadAccessTokenAsync(signup, cancellationToken), "tid")!);

        // Log in fresh to get a TENANT-LESS session plus its refresh cookie.
        var (loginToken, refreshCookie) = await LoginCapturingCookieAsync(email, cancellationToken);
        HttpTestHelpers.ReadClaim(loginToken, "tid").ShouldBeNull();

        // Select the tenant (the mint): stamps the tenant on THIS session.
        var mint = await MintTenantTokenAsync(tenantId, loginToken, cancellationToken);
        mint.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Refresh that session and assert the refreshed access token still
        // carries the same tid - rotation preserves the selected tenant.
        var refresh = await RefreshAsync(refreshCookie, cancellationToken);
        refresh.StatusCode.ShouldBe(HttpStatusCode.OK);
        string refreshedToken;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(refresh, cancellationToken))
        {
            refreshedToken = doc.RootElement.GetProperty("accessToken").GetString()!;
        }

        HttpTestHelpers.ReadClaim(refreshedToken, "tid").ShouldBe(tenantId.ToString());
    }

    [Fact]
    public async Task MembershipDirectory_IsActiveMember_TrueForMember_FalseForNonMember()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var signup = await SignupAsync(FreshEmail(), FreshSlug(), "Directory Co", cancellationToken);
        signup.StatusCode.ShouldBe(HttpStatusCode.Created);
        var ownerToken = await ReadAccessTokenAsync(signup, cancellationToken);
        var tenantId = Guid.Parse(HttpTestHelpers.ReadClaim(ownerToken, "tid")!);
        var ownerId = HttpTestHelpers.ReadSubject(ownerToken);

        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        var tenancy = scope.ServiceProvider.GetRequiredService<ITenancyApi>();

        (await tenancy.IsActiveMemberAsync(tenantId, ownerId, cancellationToken)).ShouldBeTrue();
        // A random user is not a member.
        (await tenancy.IsActiveMemberAsync(tenantId, Guid.CreateVersion7(), cancellationToken)).ShouldBeFalse();
        // The owner is not a member of some other (non-existent) tenant.
        (await tenancy.IsActiveMemberAsync(Guid.CreateVersion7(), ownerId, cancellationToken)).ShouldBeFalse();
    }

    // --- HTTP helpers -----------------------------------------------------

    private Task<HttpResponseMessage> SignupAsync(
        string email, string slug, string tenantName, CancellationToken cancellationToken) =>
        fixture.Client.PostAsJsonAsync(
            "/api/v1/signup",
            new { email, password = Password, tenantName, slug },
            cancellationToken);

    private Task<HttpResponseMessage> MintTenantTokenAsync(
        Guid tenantId, string bearer, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenants/{tenantId}/token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private Task<HttpResponseMessage> CreateNoteAsync(string bearer, string title, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sample/notes");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        // The tenant resolves from the token's tid claim, so no X-Tenant header.
        request.Headers.Add("Idempotency-Key", Guid.CreateVersion7().ToString());
        request.Content = JsonContent.Create(new { title, body = "body" });
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private async Task<List<Guid>> ListNoteIdsAsync(string bearer, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/sample/notes");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        var response = await fixture.Client.SendAsync(request, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid())
            .ToList();
    }

    private async Task<(string AccessToken, string RefreshCookie)> LoginCapturingCookieAsync(
        string email, CancellationToken cancellationToken)
    {
        var login = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password = Password }, cancellationToken);
        login.EnsureSuccessStatusCode();
        var cookie = HttpTestHelpers.ReadSetCookie(login, "starter_refresh")
            ?? throw new InvalidOperationException("Login set no refresh cookie.");
        using var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken);
        var token = doc.RootElement.GetProperty("accessToken").GetString()!;
        return (token, cookie);
    }

    private Task<HttpResponseMessage> RefreshAsync(string refreshCookie, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("X-Starter-Refresh", "1");
        request.Headers.Add("Cookie", $"starter_refresh={refreshCookie}");
        return fixture.Client.SendAsync(request, cancellationToken);
    }

    private async Task VerifyEmailForAsync(string email, CancellationToken cancellationToken)
    {
        var verificationEmail = fixture.Emails.Sent.Last(message => message.To == email);
        var token = HttpTestHelpers.ExtractVerificationToken(verificationEmail);
        var verify = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/verify-email", new { token }, cancellationToken);
        verify.EnsureSuccessStatusCode();
    }

    private static async Task<string> ReadAccessTokenAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()!;
    }

    // --- SQL helpers ------------------------------------------------------

    private async Task<long> CountAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        // Admin (superuser) connection, bypasses RLS, for direct assertions.
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static string FreshEmail() => $"prov-{Guid.NewGuid():N}@starter.example";

    private static string FreshSlug() => $"tenant-{Guid.NewGuid():N}";
}
