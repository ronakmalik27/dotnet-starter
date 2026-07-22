using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Teams as principals (multi-tenancy.md sections 13, 14, 20), driven through the
/// real endpoints. Proves: team CRUD plus add/remove/list members; a grant held
/// by a TEAM confers its permissions to a team member and removing the member
/// revokes them on the next request; a team grant at WORKSPACE scope confers only
/// in that workspace (nothing tenant-wide, nothing in another workspace); and
/// deleting a team removes its grants (a member who had a permission only via the
/// team loses it). The tenant boundary (RLS) is untouched - teams and team_members
/// are tenant-owned like everything else.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TeamTests(StarterAppFixture fixture)
{
    // Hoisted so the repeated permission argument is not a constant array literal
    // at the call site (CA1861).
    private static readonly string[] InvitationsManage = ["invitations:manage"];

    private static readonly string[] RolesManage = ["roles:manage"];

    // --- (a) Team CRUD + add/remove/list members --------------------------

    [Fact]
    public async Task TeamCrud_Create_List_Get_Rename_Members_Delete_AndDuplicateSlugRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var slug = $"team-{Guid.NewGuid():N}";

        var teamId = await TenantWorkflow.CreateTeamAsync(fixture, owner.Token, slug, "Core", cancellationToken);

        // List includes the new team.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/teams", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            doc.RootElement.EnumerateArray()
                .Select(item => item.GetProperty("id").GetGuid())
                .ShouldContain(teamId);
        }

        // Rename, then read back the new name.
        var rename = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}", owner.Token, new { name = "Core Team" }, cancellationToken);
        rename.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var get = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}", owner.Token, cancellationToken);
        get.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(get, cancellationToken))
        {
            doc.RootElement.GetProperty("name").GetString().ShouldBe("Core Team");
            doc.RootElement.GetProperty("slug").GetString().ShouldBe(slug);
        }

        // Add a member, then the member list shows them.
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var members = await TeamMemberIdsAsync(owner.Token, teamId, cancellationToken);
        members.ShouldContain(member.UserId);

        // Remove the member; the list no longer shows them.
        var remove = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}/members/{member.UserId}", owner.Token, cancellationToken);
        remove.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await TeamMemberIdsAsync(owner.Token, teamId, cancellationToken)).ShouldNotContain(member.UserId);

        // A duplicate slug in the same tenant is refused with the dedicated slug.
        var duplicate = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/teams", owner.Token, new { slug, name = "Second" }, cancellationToken);
        duplicate.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(duplicate, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:team-slug-taken");
        }

        // Delete the team; it is then gone (404 team-not-found).
        var delete = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}", owner.Token, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterDelete = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}", owner.Token, cancellationToken);
        afterDelete.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(afterDelete, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:team-not-found");
        }
    }

    [Fact]
    public async Task TeamManagement_IsAdminPlus_PlainMemberIsForbidden()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // teams:manage is Admin+, so a plain member cannot create a team.
        var create = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/teams",
            member.Token,
            new { slug = $"team-{Guid.NewGuid():N}", name = "Nope" },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    [Fact]
    public async Task AddingNonMemberUser_ToTeam_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A user who is not a member of this tenant (an owner of a DIFFERENT
        // tenant) cannot be added: a team never admits a non-member.
        var stranger = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var teamId = await TenantWorkflow.CreateTeamAsync(
            fixture, owner.Token, $"team-{Guid.NewGuid():N}", "Core", cancellationToken);

        var add = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/tenant/teams/{teamId}/members",
            owner.Token,
            new { userId = stranger.UserId },
            cancellationToken);
        add.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    // --- (b) A team grant confers to a member; removal revokes ------------

    [Fact]
    public async Task TeamGrant_ConfersToMember_AndRemovingFromTeam_RevokesOnNextRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // A team holds invitations:manage (granted TO the team, not the member).
        var teamId = await TenantWorkflow.CreateTeamAsync(
            fixture, owner.Token, $"inviters-{Guid.NewGuid():N}", "Inviters", cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, $"inviter-{Guid.NewGuid():N}", InvitationsManage, cancellationToken);
        await TenantWorkflow.AssignRoleToTeamAsync(fixture, owner.Token, roleId, teamId, cancellationToken);

        // Before joining the team, the plain member cannot invite.
        var before = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        before.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // Add the member to the team: the team's grant now confers to them.
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);

        var granted = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        granted.StatusCode.ShouldBe(HttpStatusCode.Created);

        // Remove them from the team: the grant is revoked on the very next request.
        var remove = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}/members/{member.UserId}", owner.Token, cancellationToken);
        remove.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var after = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        after.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(after, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    // --- (c) A team grant at workspace scope confers only there -----------

    [Fact]
    public async Task TeamGrant_AtWorkspaceScope_ConfersInThatWorkspaceOnly()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        // A team holds a workspace-local roles:manage role at A, and the member is
        // in the team.
        var teamId = await TenantWorkflow.CreateTeamAsync(
            fixture, owner.Token, $"ws-admins-{Guid.NewGuid():N}", "WS Admins", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceA, $"ws-admin-{Guid.NewGuid():N}", RolesManage, cancellationToken);

        var assign = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/role-assignments",
            owner.Token,
            new { roleId, teamId },
            cancellationToken);
        assign.StatusCode.ShouldBe(HttpStatusCode.Created);

        // In workspace A the member (via the team) has roles:manage: they can
        // author another workspace-local role there.
        var inA = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/roles",
            member.Token,
            new { key = $"r-{Guid.NewGuid():N}", name = "made via team", permissions = RolesManage },
            cancellationToken);
        inA.StatusCode.ShouldBe(HttpStatusCode.Created);

        // In workspace B the team grant confers nothing: 403.
        var inB = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceB}/roles",
            member.Token,
            new { key = $"r-{Guid.NewGuid():N}", name = "nope", permissions = RolesManage },
            cancellationToken);
        inB.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(inB, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }

        // Tenant-wide the team grant confers nothing (no upward inheritance): 403.
        var atTenant = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/roles",
            member.Token,
            new { key = $"r-{Guid.NewGuid():N}", name = "nope", assignableAt = "tenant", permissions = RolesManage },
            cancellationToken);
        atTenant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(atTenant, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }
    }

    // --- (d) Deleting a team removes its grants ---------------------------

    [Fact]
    public async Task DeletingTeam_RemovesItsGrants_MemberLosesPermissionHeldOnlyViaTeam()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var teamId = await TenantWorkflow.CreateTeamAsync(
            fixture, owner.Token, $"inviters-{Guid.NewGuid():N}", "Inviters", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, $"inviter-{Guid.NewGuid():N}", InvitationsManage, cancellationToken);
        await TenantWorkflow.AssignRoleToTeamAsync(fixture, owner.Token, roleId, teamId, cancellationToken);

        // The member holds invitations:manage ONLY through the team.
        var withTeam = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        withTeam.StatusCode.ShouldBe(HttpStatusCode.Created);

        // Delete the team: its grants are removed first (section 20), so the member
        // loses the permission on their next request.
        var delete = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}", owner.Token, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterDelete = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        afterDelete.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(afterDelete, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");

        // And the team's grant is gone from the roster (no dangling assignment).
        var assignments = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/role-assignments", owner.Token, cancellationToken);
        using (var assignmentsDoc = await HttpTestHelpers.ReadJsonAsync(assignments, cancellationToken))
        {
            assignmentsDoc.RootElement.EnumerateArray()
                .Select(item => item.GetProperty("principalId").GetGuid())
                .ShouldNotContain(teamId);
        }
    }

    // --- helpers ----------------------------------------------------------

    private async Task<List<Guid>> TeamMemberIdsAsync(
        string bearer, Guid teamId, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/teams/{teamId}/members", bearer, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.EnumerateArray()
            .Select(item => item.GetProperty("userId").GetGuid())
            .ToList();
    }
}
