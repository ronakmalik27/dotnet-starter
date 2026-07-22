using System.Net;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Scope-aware invitations (multi-tenancy.md section 16), driven through the real
/// endpoints. Proves: accepting an invite that carries workspace_id + role_id
/// creates BOTH the membership and the workspace-scoped role_assignment in one
/// transaction (the invitee lands "a member, and developer on the staging
/// workspace"); the invited role is validated at invite time (a role not
/// assignable at the invited scope is rejected before the invite is issued); and
/// two concurrent accepts of scope-aware invites still cannot exceed seat_limit
/// (the Part I seat-race guarantee is intact).
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class ScopeAwareInvitationTests(StarterAppFixture fixture)
{
    // Hoisted so the repeated permission argument is not a constant array literal
    // at the call site (CA1861).
    private static readonly string[] RolesManage = ["roles:manage"];

    // --- (e) A scope-aware accept creates membership + the scoped grant ---

    [Fact]
    public async Task ScopeAwareInvite_Accept_CreatesMembershipAndWorkspaceScopedGrant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        // A workspace-local role at A granting roles:manage - the scoped role the
        // invite will grant on accept.
        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceA, $"ws-admin-{Guid.NewGuid():N}", RolesManage, cancellationToken);

        // The invitee's account exists and is verified before the invite, so the
        // mailbox lookup for the invitation email is unambiguous.
        var email = TenantWorkflow.FreshEmail("scoped");
        var inviteeToken = await fixture.RegisterVerifyLoginAsync(
            email, TenantWorkflow.Password, cancellationToken);

        // Invite straight into "roles:manage on workspace A" in one step.
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email, role = "member", workspaceId = workspaceA, roleId },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var rawToken = ExtractInvitationToken(email);
        var accept = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
        accept.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tidToken = await TenantWorkflow.MintTenantTokenAsync(
            fixture, owner.TenantId, inviteeToken, cancellationToken);

        // The scoped grant confers roles:manage in workspace A: the invitee can
        // author a workspace-local role there, though their base role is member.
        var inA = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/roles",
            tidToken,
            new { key = $"r-{Guid.NewGuid():N}", name = "made by invitee", permissions = RolesManage },
            cancellationToken);
        inA.StatusCode.ShouldBe(HttpStatusCode.Created);

        // It confers nothing in workspace B (403) and nothing tenant-wide (403).
        var inB = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceB}/roles",
            tidToken,
            new { key = $"r-{Guid.NewGuid():N}", name = "nope", permissions = RolesManage },
            cancellationToken);
        inB.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        var atTenant = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/roles", tidToken, cancellationToken);
        atTenant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ScopeAwareInvite_WithRoleNotAssignableAtScope_IsRejectedAtInviteTime()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);

        // A TENANT-only role (assignableAt = tenant) cannot be granted at workspace
        // scope, so a scope-aware invite naming it is rejected at invite time.
        var tenantOnlyRole = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, $"tenant-only-{Guid.NewGuid():N}", "tenant", RolesManage, cancellationToken);

        var email = TenantWorkflow.FreshEmail("bad-scope");
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email, role = "member", workspaceId = workspaceA, roleId = tenantOnlyRole },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task ScopeAwareInvite_WithOnlyOneOfWorkspaceOrRole_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);

        // workspace_id without role_id is a malformed scope-aware invite.
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            owner.Token,
            new { email = TenantWorkflow.FreshEmail("half"), role = "member", workspaceId = workspaceA },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    // --- (f) Two concurrent scope-aware accepts hold the seat limit -------

    [Fact]
    public async Task SeatRace_TwoConcurrentScopeAwareAccepts_OnlyOneSucceeds_AndCountNeverExceedsLimit()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A workspace + a workspace-assignable role: the scoped grant each invite
        // would create on accept.
        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-{Guid.NewGuid():N}", "A", cancellationToken);
        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceId, $"ws-admin-{Guid.NewGuid():N}", RolesManage, cancellationToken);

        // seat_limit pinned to 2: the owner holds one seat, so exactly one free
        // seat and two scope-aware invitations racing for it.
        await ExecuteAsync(
            "update tenancy.tenants set seat_limit = 2 where id = @id",
            cancellationToken,
            ("id", owner.TenantId));

        var (firstEmail, firstToken, firstRaw) = await RegisterInviteeAsync("race-a", cancellationToken);
        var (secondEmail, secondToken, secondRaw) = await RegisterInviteeAsync("race-b", cancellationToken);

        await SeedScopedInvitationAsync(
            owner.TenantId, owner.UserId, firstEmail, firstRaw, workspaceId, roleId, cancellationToken);
        await SeedScopedInvitationAsync(
            owner.TenantId, owner.UserId, secondEmail, secondRaw, workspaceId, roleId, cancellationToken);

        // Fire both accepts concurrently. They serialize on the tenant row lock.
        var firstAccept = TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", firstToken, new { token = firstRaw }, cancellationToken);
        var secondAccept = TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", secondToken, new { token = secondRaw }, cancellationToken);
        var responses = await Task.WhenAll(firstAccept, secondAccept);

        var statuses = responses.Select(response => response.StatusCode).ToList();
        statuses.Count(status => status == HttpStatusCode.OK).ShouldBe(1);
        statuses.Count(status => status == HttpStatusCode.Conflict).ShouldBe(1);

        var rejected = responses.Single(response => response.StatusCode == HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(rejected, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-seat-limit-reached");
        }

        // The invariant: the active-member count reached the limit and never went
        // past it, even though each accept ALSO wrote a scoped grant.
        var activeMembers = await CountAsync(
            "select count(*) from tenancy.memberships where tenant_id = @id and status = 'active'",
            cancellationToken,
            ("id", owner.TenantId));
        activeMembers.ShouldBe(2);

        // Exactly one workspace-scoped grant was created (the winning accept), so
        // the grant write is bound to the same transaction as the seat check.
        var grants = await CountAsync(
            "select count(*) from tenancy.role_assignments "
            + "where tenant_id = @id and scope_type = 'workspace' and scope_id = @ws and role_id = @role",
            cancellationToken,
            ("id", owner.TenantId),
            ("ws", workspaceId),
            ("role", roleId));
        grants.ShouldBe(1);
    }

    // --- helpers ----------------------------------------------------------

    private async Task<(string Email, string Token, string RawToken)> RegisterInviteeAsync(
        string tag, CancellationToken cancellationToken)
    {
        var email = TenantWorkflow.FreshEmail(tag);
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var rawToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        return (email, token, rawToken);
    }

    private async Task SeedScopedInvitationAsync(
        Guid tenantId,
        Guid invitedBy,
        string email,
        string rawToken,
        Guid workspaceId,
        Guid roleId,
        CancellationToken cancellationToken)
    {
        // Seed on the admin (superuser) connection, which bypasses RLS, so the
        // test can plant a scope-aware invitation with a token hash it controls.
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into tenancy.invitations "
            + "(id, tenant_id, email, role, token_hash, expires_at, accepted_at, workspace_id, role_id, invited_by, created_at) "
            + "values (@id, @tenant, @email, 'member', @hash, now() + interval '1 day', null, @ws, @role, @invitedBy, now())",
            connection);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("email", email);
        command.Parameters.AddWithValue("hash", HashToken(rawToken));
        command.Parameters.AddWithValue("ws", workspaceId);
        command.Parameters.AddWithValue("role", roleId);
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
