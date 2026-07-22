using System.Net;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Invitations and acceptance (multi-tenancy.md section 8), driven through the
/// real endpoints. Proves: an invited email accepts and becomes an active member;
/// the token is single-use; a mismatched-email account cannot accept; and two
/// concurrent accepts at a one-seat gap cannot both succeed - the seat limit
/// holds under a tenant row lock and the count never exceeds it.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TenantInvitationTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task Invite_ThenAccept_MakesActiveMember_AndTokenIsSingleUse()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var inviteeEmail = TenantWorkflow.FreshEmail("invitee");
        var inviteeToken = await fixture.RegisterVerifyLoginAsync(
            inviteeEmail, TenantWorkflow.Password, cancellationToken);

        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email = inviteeEmail, role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var rawToken = ExtractInvitationToken(inviteeEmail);

        // First accept: joins the tenant with the invited role.
        var accept = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
        accept.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(accept, cancellationToken))
        {
            doc.RootElement.GetProperty("tenantId").GetGuid().ShouldBe(owner.TenantId);
            doc.RootElement.GetProperty("role").GetString().ShouldBe("member");
        }

        // Now an active member: the tid-token mint (which checks active
        // membership on the bypass path) succeeds.
        var mint = await TenantWorkflow.MintTenantTokenAsync(
            fixture, owner.TenantId, inviteeToken, cancellationToken);
        mint.ShouldNotBeNullOrEmpty();

        // Single-use: a second accept of the same (now consumed) token fails
        // cleanly with the generic invalid outcome.
        var second = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
        second.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(second, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-invitation-invalid");
        }
    }

    [Fact]
    public async Task Accept_ByMismatchedEmailAccount_IsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Invite one email, but redeem the link from a DIFFERENT authenticated
        // account: a leaked link must not be redeemable by another account.
        var invitedEmail = TenantWorkflow.FreshEmail("invited");
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email = invitedEmail, role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);
        var rawToken = ExtractInvitationToken(invitedEmail);

        var strangerToken = await fixture.RegisterVerifyLoginAsync(
            TenantWorkflow.FreshEmail("stranger"), TenantWorkflow.Password, cancellationToken);

        var accept = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", strangerToken, new { token = rawToken }, cancellationToken);
        accept.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using var doc = await HttpTestHelpers.ReadJsonAsync(accept, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-invitation-invalid");
    }

    [Fact]
    public async Task SeatRace_TwoConcurrentAccepts_OnlyOneSucceeds_AndCountNeverExceedsLimit()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // seat_limit-1 active members: the owner (1) with seat_limit pinned to 2,
        // so exactly one free seat and two invitations racing for it.
        await ExecuteAsync(
            "update tenancy.tenants set seat_limit = 2 where id = @id",
            cancellationToken,
            ("id", owner.TenantId));

        var (firstEmail, firstToken, firstRaw) = await RegisterInviteeAsync("race-a", cancellationToken);
        var (secondEmail, secondToken, secondRaw) = await RegisterInviteeAsync("race-b", cancellationToken);

        await SeedInvitationAsync(owner.TenantId, owner.UserId, firstEmail, firstRaw, cancellationToken);
        await SeedInvitationAsync(owner.TenantId, owner.UserId, secondEmail, secondRaw, cancellationToken);

        // Fire both accepts concurrently. They serialize on the tenant row lock.
        var firstAccept = TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", firstToken, new { token = firstRaw }, cancellationToken);
        var secondAccept = TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", secondToken, new { token = secondRaw }, cancellationToken);
        var responses = await Task.WhenAll(firstAccept, secondAccept);

        var statuses = responses.Select(response => response.StatusCode).ToList();
        statuses.Count(status => status == HttpStatusCode.OK).ShouldBe(1);
        statuses.Count(status => status == HttpStatusCode.Conflict).ShouldBe(1);

        // The rejected one is specifically the seat-limit conflict.
        var rejected = responses.Single(response => response.StatusCode == HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(rejected, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-seat-limit-reached");
        }

        // The invariant: the active-member count reached the limit and never went
        // past it.
        var activeMembers = await CountAsync(
            "select count(*) from tenancy.memberships where tenant_id = @id and status = 'active'",
            cancellationToken,
            ("id", owner.TenantId));
        activeMembers.ShouldBe(2);
    }

    // --- helpers ----------------------------------------------------------

    private async Task<(string Email, string Token, string RawToken)> RegisterInviteeAsync(
        string tag, CancellationToken cancellationToken)
    {
        var email = TenantWorkflow.FreshEmail(tag);
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        // A raw token the test controls, whose SHA-256 hex it seeds as token_hash.
        var rawToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        return (email, token, rawToken);
    }

    private async Task SeedInvitationAsync(
        Guid tenantId, Guid invitedBy, string email, string rawToken, CancellationToken cancellationToken)
    {
        // Seed on the admin (superuser) connection, which bypasses RLS, so the
        // test can plant an invitation directly with a token hash it controls.
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into tenancy.invitations "
            + "(id, tenant_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at) "
            + "values (@id, @tenant, @email, 'member', @hash, now() + interval '1 day', null, @invitedBy, now())",
            connection);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("email", email);
        command.Parameters.AddWithValue("hash", HashToken(rawToken));
        command.Parameters.AddWithValue("invitedBy", invitedBy);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string HashToken(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private string ExtractInvitationToken(string email)
    {
        var invitationEmail = fixture.Emails.Sent.Last(
            message => message.To == email && message.Subject.Contains("invited", StringComparison.Ordinal));
        return HttpTestHelpers.ExtractVerificationToken(invitationEmail);
    }

    private async Task<long> CountAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task ExecuteAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
