using System.Net;
using System.Net.Http.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The tenant-admin control-plane API (multi-tenancy.md section 8): member role
/// and removal constraints, settings updates, ownership transfer, soft-delete,
/// and seats. Driven through the real endpoints.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TenantAdminTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task ChangeRole_CannotPromoteToOwner_ViaPatch()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var promote = await TenantWorkflow.PatchJsonAsync(
            fixture,
            $"/api/v1/tenant/members/{member.UserId}",
            owner.Token,
            new { role = "owner" },
            cancellationToken);

        promote.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task ChangeRole_CannotDemote_TheLastOwner()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);

        // The admin tries to demote the sole owner to member: refused (last owner).
        var demote = await TenantWorkflow.PatchJsonAsync(
            fixture,
            $"/api/v1/tenant/members/{owner.UserId}",
            admin.Token,
            new { role = "member" },
            cancellationToken);

        demote.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var doc = await HttpTestHelpers.ReadJsonAsync(demote, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-last-owner");
    }

    [Fact]
    public async Task RemoveMember_CannotRemove_TheLastOwner()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);

        var remove = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/members/{owner.UserId}", admin.Token, cancellationToken);

        remove.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var doc = await HttpTestHelpers.ReadJsonAsync(remove, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-last-owner");
    }

    [Fact]
    public async Task ChangeRole_And_RemoveMember_HappyPaths()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // Promote member -> admin (allowed).
        var promote = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/members/{member.UserId}", owner.Token, new { role = "admin" }, cancellationToken);
        promote.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await RoleOfAsync(owner.TenantId, member.UserId, cancellationToken)).ShouldBe("admin");

        // Remove the (now admin) member (allowed - not the last owner).
        var remove = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/members/{member.UserId}", owner.Token, cancellationToken);
        remove.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await CountAsync(
            "select count(*) from tenancy.memberships where tenant_id = @tid and user_id = @uid",
            cancellationToken, ("tid", owner.TenantId), ("uid", member.UserId)))
            .ShouldBe(0);
    }

    [Fact]
    public async Task UpdateSettings_NameChangeSucceeds_SlugCollisionIs409()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Name change succeeds.
        var rename = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/tenant", owner.Token, new { name = "Renamed Co" }, cancellationToken);
        rename.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await ScalarStringAsync(
            "select name from tenancy.tenants where id = @id", cancellationToken, ("id", owner.TenantId)))
            .ShouldBe("Renamed Co");

        // A second tenant claims a slug; the first tenant cannot take it -> 409.
        var takenSlug = TenantWorkflow.FreshSlug();
        var other = await fixture.Client.PostAsJsonAsync(
            "/api/v1/signup",
            new { email = TenantWorkflow.FreshEmail("other"), password = TenantWorkflow.Password, tenantName = "Other", slug = takenSlug },
            cancellationToken);
        other.StatusCode.ShouldBe(HttpStatusCode.Created);

        var collide = await TenantWorkflow.PatchJsonAsync(
            fixture, "/api/v1/tenant", owner.Token, new { slug = takenSlug }, cancellationToken);
        collide.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var doc = await HttpTestHelpers.ReadJsonAsync(collide, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-slug-taken");
    }

    [Fact]
    public async Task TransferOwnership_SwapsRoles_OwnerStepsDownToAdmin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var transfer = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/transfer-ownership", owner.Token, new { userId = member.UserId }, cancellationToken);
        transfer.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await RoleOfAsync(owner.TenantId, member.UserId, cancellationToken)).ShouldBe("owner");
        (await RoleOfAsync(owner.TenantId, owner.UserId, cancellationToken)).ShouldBe("admin");
    }

    [Fact]
    public async Task SoftDelete_SetsTenantStatusToDeleted()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var delete = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/delete", owner.Token, new { }, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await ScalarStringAsync(
            "select status from tenancy.tenants where id = @id", cancellationToken, ("id", owner.TenantId)))
            .ShouldBe("deleted");
    }

    [Fact]
    public async Task Seats_ReportsLimitAndActiveCount()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var before = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/seats", owner.Token, cancellationToken);
        before.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(before, cancellationToken))
        {
            doc.RootElement.GetProperty("seatLimit").GetInt32().ShouldBe(5);
            doc.RootElement.GetProperty("activeMembers").GetInt32().ShouldBe(1);
        }

        await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var after = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/seats", owner.Token, cancellationToken);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(after, cancellationToken))
        {
            doc.RootElement.GetProperty("activeMembers").GetInt32().ShouldBe(2);
        }
    }

    [Fact]
    public async Task ListMembers_ReturnsTheTenantMembers()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var response = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/members", owner.Token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);

        var userIds = doc.RootElement.EnumerateArray()
            .Select(item => item.GetProperty("userId").GetGuid())
            .ToList();
        userIds.ShouldContain(owner.UserId);
        userIds.ShouldContain(member.UserId);
    }

    // --- SQL helpers ------------------------------------------------------

    private Task<string?> RoleOfAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        ScalarStringAsync(
            "select role from tenancy.memberships where tenant_id = @tid and user_id = @uid",
            cancellationToken, ("tid", tenantId), ("uid", userId));

    private async Task<string?> ScalarStringAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return (await command.ExecuteScalarAsync(cancellationToken)) as string;
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
}
