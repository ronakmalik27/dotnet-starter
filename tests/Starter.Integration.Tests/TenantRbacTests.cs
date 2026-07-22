using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The RBAC capability layer (multi-tenancy.md section 5, layer 2) and ownership
/// within a tenant (layer 3), driven through the real endpoints. Proves: a plain
/// member is refused member-management (403 starter:tenant-role-required); an
/// admin is granted it; an owner-only operation refuses an admin; and a
/// tenant-admin may manage any resource in the tenant while a plain member may
/// not cross to another member's resource.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TenantRbacTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task Member_IsRefused_MemberManagement_With403RoleRequired()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // A plain member cannot invite (an admin+ action).
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("nope"), role = "member" },
            cancellationToken);

        invite.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(invite, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-role-required");
    }

    [Fact]
    public async Task Admin_IsGranted_MemberManagement()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);

        // The admin can list members and invite - both granted at admin+.
        var members = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/members", admin.Token, cancellationToken);
        members.StatusCode.ShouldBe(HttpStatusCode.OK);

        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            admin.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Admin_IsRefused_OwnerOnlyOperation_With403()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);

        // Transfer-ownership is owner-only; an admin is refused by the role gate.
        var transfer = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/transfer-ownership",
            admin.Token,
            new { userId = owner.UserId },
            cancellationToken);

        transfer.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(transfer, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-role-required");

        // Soft-delete is owner-only too.
        var delete = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/delete", admin.Token, new { }, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task TenantAdmin_ManagesAnyResource_ButAPlainMemberCannotCross()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // Two notes in the one tenant: one owned by the owner, one by the member.
        var ownerNoteId = await CreateNoteAsync(owner.Token, "Owner note", cancellationToken);
        var memberNoteId = await CreateNoteAsync(member.Token, "Member note", cancellationToken);

        // A plain member cannot read the owner's note: not the owner of it, not an
        // admin+ in the tenant -> 403 (both handlers stay silent).
        var memberReadsOwners = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{ownerNoteId}", member.Token, cancellationToken);
        memberReadsOwners.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // The owner (admin+ in the tenant) CAN read the member's note, though the
        // owner does not own it - the tenant-admin resource handler grants it.
        var ownerReadsMembers = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{memberNoteId}", owner.Token, cancellationToken);
        ownerReadsMembers.StatusCode.ShouldBe(HttpStatusCode.OK);

        // And the owner can delete it too (admin+ manages any resource).
        var ownerDeletesMembers = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/sample/notes/{memberNoteId}", owner.Token, cancellationToken);
        ownerDeletesMembers.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task<Guid> CreateNoteAsync(string bearer, string title, CancellationToken cancellationToken)
    {
        var create = await TenantWorkflow.CreateNoteAsync(fixture, bearer, title, cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }
}
