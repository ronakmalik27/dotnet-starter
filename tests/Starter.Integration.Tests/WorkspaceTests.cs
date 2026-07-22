using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Workspaces as an authorization scope INSIDE the tenant (multi-tenancy.md
/// sections 12, 13, 15), driven through the real endpoints. Proves: workspace
/// CRUD and the tenant-scope permission catalogue for it; a workspace-scoped
/// grant confers ONLY in its workspace (nothing tenant-wide, nothing in another
/// workspace); a tenant-scope grant inherits DOWN into every workspace; a
/// workspace-local role cannot be assigned outside its workspace; workspace note
/// isolation within a tenant; and that a workspace from another tenant is 404 by
/// RLS (never 403). The tenant boundary is untouched throughout - a workspace is
/// scoped RBAC plus a workspace_id column, not a second RLS tier.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class WorkspaceTests(StarterAppFixture fixture)
{
    // Hoisted so the repeated permission argument is not a constant array literal
    // at the call site (CA1861).
    private static readonly string[] RolesManage = ["roles:manage"];

    // --- (a) Workspace CRUD ----------------------------------------------

    [Fact]
    public async Task WorkspaceCrud_Create_List_Rename_Archive_And_DuplicateSlugRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var slug = $"ws-{Guid.NewGuid():N}";

        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, slug, "Production", cancellationToken);

        // List includes the new workspace.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/workspaces", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            doc.RootElement.EnumerateArray()
                .Select(item => item.GetProperty("id").GetGuid())
                .ShouldContain(workspaceId);
        }

        // Rename, then read back the new name.
        var rename = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}", owner.Token, new { name = "Prod" }, cancellationToken);
        rename.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterRename = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}", owner.Token, cancellationToken);
        afterRename.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(afterRename, cancellationToken))
        {
            doc.RootElement.GetProperty("name").GetString().ShouldBe("Prod");
        }

        // Archive transitions active -> archived.
        var archive = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}/archive", owner.Token, new { }, cancellationToken);
        archive.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterArchive = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}", owner.Token, cancellationToken);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(afterArchive, cancellationToken))
        {
            doc.RootElement.GetProperty("status").GetString().ShouldBe("archived");
        }

        // A duplicate slug in the same tenant is refused with the dedicated slug.
        var duplicate = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/workspaces", owner.Token, new { slug, name = "Second" }, cancellationToken);
        duplicate.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(duplicate, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:workspace-slug-taken");
        }
    }

    [Fact]
    public async Task WorkspaceManagement_IsAdminPlus_ReadIsMemberPlus()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // workspaces:read is Member+, so a plain member can list workspaces.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/workspaces", member.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);

        // workspaces:manage is Admin+, so a plain member cannot create one.
        var create = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/workspaces",
            member.Token,
            new { slug = $"ws-{Guid.NewGuid():N}", name = "Nope" },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    // --- (b) A workspace-scoped grant confers only in its workspace -------

    [Fact]
    public async Task WorkspaceScopedGrant_ConfersInThatWorkspaceOnly_NothingTenantWide_NothingElsewhere()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        // Owner (roles:manage inherits into every workspace) authors a
        // workspace-local role at A granting roles:manage and assigns it to the
        // plain member at A.
        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceA, "ws-admin", RolesManage, cancellationToken);
        var assign = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/role-assignments",
            owner.Token,
            new { roleId, userId = member.UserId },
            cancellationToken);
        assign.StatusCode.ShouldBe(HttpStatusCode.Created);

        // In workspace A the member now has roles:manage: they can author another
        // workspace-local role there.
        var inA = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/roles",
            member.Token,
            new { key = $"r-{Guid.NewGuid():N}", name = "made by member", permissions = RolesManage },
            cancellationToken);
        inA.StatusCode.ShouldBe(HttpStatusCode.Created);

        // In workspace B the grant confers nothing: 403.
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

        // Tenant-wide the grant confers nothing: the tenant roles plane is 403
        // (no upward inheritance from a workspace grant).
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

    // --- (c) A tenant-scope grant inherits down into every workspace ------

    [Fact]
    public async Task TenantScopedGrant_IsHonoredInEveryWorkspace_DownwardInheritance()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        // A TENANT-scope grant of roles:manage.
        var roleId = await TenantWorkflow.CreateRoleAsync(
            fixture, owner.Token, $"tenant-admin-{Guid.NewGuid():N}", "tenant", RolesManage, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, member.UserId, cancellationToken);

        // It is honored in BOTH workspaces (downward inheritance): the member can
        // author a workspace-local role in each.
        foreach (var workspaceId in new[] { workspaceA, workspaceB })
        {
            var response = await TenantWorkflow.PostJsonAsync(
                fixture,
                $"/api/v1/workspaces/{workspaceId}/roles",
                member.Token,
                new { key = $"r-{Guid.NewGuid():N}", name = "inherited", permissions = RolesManage },
                cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.Created);
        }
    }

    // --- (d) A workspace-local role cannot be assigned outside its workspace

    [Fact]
    public async Task WorkspaceLocalRole_AssignedAtTenantScope_OrAnotherWorkspace_IsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceA, "a-local", RolesManage, cancellationToken);

        // Assigning it at TENANT scope is rejected (a workspace-local role never
        // reaches tenant scope).
        var atTenant = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/role-assignments",
            owner.Token,
            new { roleId, userId = member.UserId },
            cancellationToken);
        atTenant.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // Assigning it at a DIFFERENT workspace (B) is rejected (scope_id must
        // equal the role's owning workspace).
        var atOtherWorkspace = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceB}/role-assignments",
            owner.Token,
            new { roleId, userId = member.UserId },
            cancellationToken);
        atOtherWorkspace.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // At its OWN workspace it assigns fine, proving the rejections above are
        // the scope rule, not a broken role.
        var atOwnWorkspace = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceA}/role-assignments",
            owner.Token,
            new { roleId, userId = member.UserId },
            cancellationToken);
        atOwnWorkspace.StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    // --- (e) Workspace note isolation within a tenant ---------------------

    [Fact]
    public async Task WorkspaceNotes_AreIsolatedPerWorkspace_TenantListSpansBoth_OtherTenantIs404()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var workspaceA = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-a-{Guid.NewGuid():N}", "A", cancellationToken);
        var workspaceB = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-b-{Guid.NewGuid():N}", "B", cancellationToken);

        var noteA = await CreateWorkspaceNoteAsync(owner.Token, workspaceA, "in A", cancellationToken);
        var noteB = await CreateWorkspaceNoteAsync(owner.Token, workspaceB, "in B", cancellationToken);

        // Workspace A lists A's note, not B's; and vice versa (app-level filter).
        var inA = await WorkspaceNoteIdsAsync(owner.Token, workspaceA, cancellationToken);
        inA.ShouldContain(noteA);
        inA.ShouldNotContain(noteB);

        var inB = await WorkspaceNoteIdsAsync(owner.Token, workspaceB, cancellationToken);
        inB.ShouldContain(noteB);
        inB.ShouldNotContain(noteA);

        // The tenant-level list spans both workspaces (the owner sees across them).
        var tenantList = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/sample/notes", owner.Token, cancellationToken);
        tenantList.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(tenantList, cancellationToken))
        {
            var ids = doc.RootElement.GetProperty("items").EnumerateArray()
                .Select(item => item.GetProperty("id").GetGuid())
                .ToList();
            ids.ShouldContain(noteA);
            ids.ShouldContain(noteB);
        }

        // Another tenant cannot even see workspace A: 404 by RLS (the tenant
        // boundary is untouched), never a cross-tenant note.
        var otherTenant = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var crossTenant = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/workspaces/{workspaceA}/sample/notes", otherTenant.Token, cancellationToken);
        crossTenant.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(crossTenant, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:workspace-not-found");
        }
    }

    // --- (f) A workspace from another tenant is 404, not 403 --------------

    [Fact]
    public async Task WorkspaceFromAnotherTenant_Is404WorkspaceNotFound_Not403()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-{Guid.NewGuid():N}", "A", cancellationToken);

        // A second tenant's owner holds roles:manage tenant-wide, so if the
        // workspace were in their tenant the permission gate would pass. Because
        // it is another tenant's workspace it is invisible under RLS, so the
        // existence gate answers 404 - never 403, which would confirm it exists.
        var otherTenant = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var response = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}/roles", otherTenant.Token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:workspace-not-found");
    }

    // --- Archive enforcement: read-only, reversible -----------------------

    [Fact]
    public async Task ArchivedWorkspace_IsReadOnly_WritesAre409_ReadsSucceed_UnarchiveRestoresWrites()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, $"ws-{Guid.NewGuid():N}", "A", cancellationToken);

        // A note and a workspace-local role while the workspace is still active,
        // so the archived-state checks below are the block, not a missing prereq.
        var existingNote = await CreateWorkspaceNoteAsync(owner.Token, workspaceId, "before archive", cancellationToken);
        var roleId = await TenantWorkflow.CreateWorkspaceRoleAsync(
            fixture, owner.Token, workspaceId, "ws-role", RolesManage, cancellationToken);

        var archive = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}/archive", owner.Token, new { }, cancellationToken);
        archive.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // (i) A write to a resource inside the archived workspace is refused 409.
        var blockedNote = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceId}/sample/notes",
            owner.Token,
            new { title = "after archive", body = "body" },
            cancellationToken);
        blockedNote.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(blockedNote, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:workspace-archived");
        }

        // (ii) Reads stay fully served: the archived workspace's notes list is 200
        // and still shows the note created before archiving (read-only, not blocked).
        var readBack = await WorkspaceNoteIdsAsync(owner.Token, workspaceId, cancellationToken);
        readBack.ShouldContain(existingNote);

        // (iii) A new workspace-scoped grant in the archived workspace is 409.
        var blockedAssign = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceId}/role-assignments",
            owner.Token,
            new { roleId, userId = owner.UserId },
            cancellationToken);
        blockedAssign.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(blockedAssign, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:workspace-archived");
        }

        // (iv) Unarchive restores writes: creating a note succeeds again.
        var unarchive = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}/unarchive", owner.Token, new { }, cancellationToken);
        unarchive.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var afterUnarchive = await CreateWorkspaceNoteAsync(
            owner.Token, workspaceId, "after unarchive", cancellationToken);
        afterUnarchive.ShouldNotBe(Guid.Empty);
    }

    // --- helpers ----------------------------------------------------------

    private async Task<Guid> CreateWorkspaceNoteAsync(
        string bearer, Guid workspaceId, string title, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture,
            $"/api/v1/workspaces/{workspaceId}/sample/notes",
            bearer,
            new { title, body = "body" },
            cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<List<Guid>> WorkspaceNoteIdsAsync(
        string bearer, Guid workspaceId, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/workspaces/{workspaceId}/sample/notes", bearer, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid())
            .ToList();
    }
}
