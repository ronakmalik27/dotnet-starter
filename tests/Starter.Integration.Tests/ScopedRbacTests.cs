using System.Net;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The scoped-RBAC engine and custom roles (multi-tenancy.md sections 13, 15),
/// driven through the real endpoints. Proves: the Part I tenant-role thresholds
/// are preserved after the endpoints migrated to RequirePermission (a plain
/// member still reads members and seats); a custom role confers exactly its
/// permissions to a member and no more; editing a role changes effective
/// permissions on the next request; the catalogue and uniqueness guardrails;
/// delete-in-use is refused; a suspended member's grants confer nothing; and
/// RequirePermission answers 403 starter:permission-required when the permission
/// is absent.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class ScopedRbacTests(StarterAppFixture fixture)
{
    // Hoisted out of the call sites so the repeated helper argument is not a
    // constant array literal (CA1861).
    private static readonly string[] InvitationsManage = ["invitations:manage"];

    private static readonly string[] MembersRead = ["members:read"];

    private static readonly string[] OwnerReservedDelete = ["tenant:delete"];

    [Fact]
    public async Task Member_StillReads_MembersAndSeats_AfterPermissionMigration()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // members:read and seats:read are in the Member system-role set, so the
        // Part I member-level read access survives the migration to permissions.
        var members = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/members", member.Token, cancellationToken);
        members.StatusCode.ShouldBe(HttpStatusCode.OK);

        var seats = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/seats", member.Token, cancellationToken);
        seats.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task CustomRole_GrantingInvitationsManage_LetsHolderInvite_ButNotUngrantedMember()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var granted = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var ungranted = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, "inviter", InvitationsManage, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, granted.UserId, cancellationToken);

        // The granted member can now invite, though their base role is member.
        var grantedInvite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            granted.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        grantedInvite.StatusCode.ShouldBe(HttpStatusCode.Created);

        // The ungranted member is still refused, with the fine-grained slug.
        var ungrantedInvite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            ungranted.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        ungrantedInvite.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(ungrantedInvite, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    [Fact]
    public async Task EditingRolePermissions_ChangesEffectivePermissions_OnNextRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, "inviter", InvitationsManage, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, member.UserId, cancellationToken);

        // With the grant, the member can invite.
        var before = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        before.StatusCode.ShouldBe(HttpStatusCode.Created);

        // Edit the role to drop invitations:manage (swap it for a harmless read).
        var edit = await TenantWorkflow.PatchJsonAsync(
            fixture,
            $"/api/v1/tenant/roles/{roleId}",
            owner.Token,
            new { permissions = MembersRead },
            cancellationToken);
        edit.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The very next request no longer carries invitations:manage.
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

    [Fact]
    public async Task CreatingRole_WithOwnerReservedPermission_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var create = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/roles",
            owner.Token,
            new { key = "sneaky", name = "Sneaky", assignableAt = "tenant", permissions = OwnerReservedDelete },
            cancellationToken);

        // Owner-reserved permissions are never grantable in a custom role.
        create.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task CreatingRole_WithDuplicateKey_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "support", MembersRead, cancellationToken);

        var duplicate = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/roles",
            owner.Token,
            new { key = "support", name = "Support Again", assignableAt = "tenant", permissions = MembersRead },
            cancellationToken);

        duplicate.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var doc = await HttpTestHelpers.ReadJsonAsync(duplicate, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-role-key-taken");
    }

    [Fact]
    public async Task DeletingRole_InUse_IsRejected_UntilRevoked()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, "inuse", MembersRead, cancellationToken);
        var assignmentId = await TenantWorkflow.AssignRoleAsync(
            fixture, owner.Token, roleId, member.UserId, cancellationToken);

        // A role with a live assignment cannot be deleted.
        var blocked = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/roles/{roleId}", owner.Token, cancellationToken);
        blocked.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(blocked, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-role-in-use");
        }

        // Revoke the assignment, then the delete succeeds.
        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/role-assignments/{assignmentId}", owner.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var deleted = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/roles/{roleId}", owner.Token, cancellationToken);
        deleted.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task SuspendedMember_Grants_ConferNothing()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, "inviter", InvitationsManage, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, member.UserId, cancellationToken);

        // While active, the grant lets the member invite.
        var active = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        active.StatusCode.ShouldBe(HttpStatusCode.Created);

        // Suspend the membership (no Part I API sets a membership suspended, so
        // the test drives it through SQL on the admin connection). The resolver
        // considers only active memberships, so all grants must now confer
        // nothing - the suspension takes effect on the next request.
        await SuspendMembershipAsync(owner.TenantId, member.UserId, cancellationToken);

        var suspended = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        suspended.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(suspended, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    [Fact]
    public async Task RequirePermission_Returns403PermissionRequired_WhenAbsent()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // A plain member holds no roles:manage, so the roles control plane is
        // refused with the fine-grained slug.
        var listRoles = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/roles", member.Token, cancellationToken);
        listRoles.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(listRoles, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    private async Task SuspendMembershipAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "update tenancy.memberships set status = 'suspended' where tenant_id = @tid and user_id = @uid",
            connection);
        command.Parameters.AddWithValue("tid", tenantId);
        command.Parameters.AddWithValue("uid", userId);
        (await command.ExecuteNonQueryAsync(cancellationToken)).ShouldBe(1);
    }
}
