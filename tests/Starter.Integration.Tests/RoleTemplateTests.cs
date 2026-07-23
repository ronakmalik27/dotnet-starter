using System.Net;
using System.Text.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Global role templates (role-templates-and-policy-defaults.md section 2), driven
/// through the real endpoints. Proves: super-admin CRUD with permission-atom
/// validation and owner-reserved rejection, and a non-super-admin refused;
/// provisioning seeds active templates as tenant custom roles (the full set on the
/// unrestricted default plan, the plan-allowed subset on a restrictive plan);
/// re-seed is idempotent via the template_key guard; a tenant edits and deletes a
/// seeded role through the existing custom-role API; and seeding to a tenant that
/// was provisioned before the template existed works.
/// <para>
/// The template catalogue is a global platform table and the integration collection
/// shares one database, so every test DELETES the templates it creates in a finally
/// (directly on the admin connection, the most reliable cleanup) - otherwise a
/// leftover template would seed into every later test's signup.
/// </para>
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class RoleTemplateTests(StarterAppFixture fixture)
{
    private const string MembersRead = "members:read";
    private const string NotesWrite = "notes:write";
    private const string RolesManage = "roles:manage";
    private const string OwnerReserved = "tenant:manage";

    // Hoisted so the repeated array arguments are not constant array literals (CA1861).
    private static readonly string[] TenantScope = ["tenant"];
    private static readonly string[] MembersReadOnly = [MembersRead];
    private static readonly string[] MembersReadAndNotesWrite = [MembersRead, NotesWrite];
    private static readonly string[] MembersReadAndRolesManage = [MembersRead, RolesManage];
    private static readonly string[] UnknownPermission = ["bogus:permission"];
    private static readonly string[] OwnerReservedPermission = [OwnerReserved];

    [Fact]
    public async Task SuperAdminCrud_ValidatesPermissionAtoms_RejectsOwnerReserved_AndRefusesNonAdmin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var key = FreshTemplateKey();

        try
        {
            // A valid template is created.
            var created = await CreateTemplateRawAsync(
                admin.Token,
                new { key, name = "Support", description = "Support desk", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);
            created.StatusCode.ShouldBe(HttpStatusCode.NoContent);

            // A duplicate key is a 409 with the dedicated slug.
            var duplicate = await CreateTemplateRawAsync(
                admin.Token,
                new { key, name = "Support again", description = "dup", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);
            duplicate.StatusCode.ShouldBe(HttpStatusCode.Conflict);
            using (var doc = await HttpTestHelpers.ReadJsonAsync(duplicate, cancellationToken))
            {
                doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-role-template-key-taken");
            }

            // An unknown permission atom is rejected (422 validation).
            var unknown = await CreateTemplateRawAsync(
                admin.Token,
                new { key = FreshTemplateKey(), name = "Bad", description = "x", permissions = UnknownPermission, assignableScopes = TenantScope },
                cancellationToken);
            unknown.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

            // An owner-reserved permission can never be templated into a tenant role.
            var reserved = await CreateTemplateRawAsync(
                admin.Token,
                new { key = FreshTemplateKey(), name = "Reserved", description = "x", permissions = OwnerReservedPermission, assignableScopes = TenantScope },
                cancellationToken);
            reserved.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

            // A plain tenant owner (not a platform admin) is refused the catalogue.
            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            var refused = await CreateTemplateRawAsync(
                owner.Token,
                new { key = FreshTemplateKey(), name = "Nope", description = "x", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);
            refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
            using (var doc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken))
            {
                doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-admin-required");
            }
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    [Fact]
    public async Task Provisioning_SeedsActiveTemplates_AsTenantCustomRoles_FullSetOnUnrestrictedPlan()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var key = FreshTemplateKey();

        try
        {
            await CreateTemplateAsync(
                admin.Token,
                new { key, name = "Editor", description = "Notes editor", permissions = MembersReadAndNotesWrite, assignableScopes = TenantScope },
                cancellationToken);

            // A fresh signup lands on the unrestricted default (free) plan, so the
            // seeded role carries the FULL template permission set.
            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

            var seeded = await FindSeededRoleAsync(owner.Token, key, cancellationToken);
            seeded.ShouldNotBeNull();
            seeded.Value.Permissions.ShouldBe(MembersReadAndNotesWrite, ignoreOrder: true);
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    [Fact]
    public async Task Seeding_RespectsPlan_SkipsDisallowedPermissions()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var planKey = FreshPlanKey();
        var key = FreshTemplateKey();

        try
        {
            // A restrictive plan whose grantable-permission catalogue omits roles:manage.
            await CreatePlanAsync(
                admin.Token,
                new { key = planKey, name = "Members only", permissions = MembersReadOnly, limits = new { seatLimit = 5 } },
                cancellationToken);

            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

            // The template asks for a permission the plan grants AND one it does not.
            await CreateTemplateAsync(
                admin.Token,
                new { key, name = "Elevated", description = "x", permissions = MembersReadAndRolesManage, assignableScopes = TenantScope },
                cancellationToken);

            var seeded = await SeedTemplateAsync(admin.Token, key, owner.TenantId, cancellationToken);
            seeded.ShouldBe(1);

            // roles:manage is SKIPPED (not in the plan); members:read is kept - a
            // template never escalates past the plan.
            var role = await FindSeededRoleAsync(owner.Token, key, cancellationToken);
            role.ShouldNotBeNull();
            role.Value.Permissions.ShouldBe(MembersReadOnly);
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    [Fact]
    public async Task Reseed_IsIdempotent_ViaTheTemplateKeyGuard()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var key = FreshTemplateKey();

        try
        {
            await CreateTemplateAsync(
                admin.Token,
                new { key, name = "Support", description = "x", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);

            // Provisioning already seeded the template into this tenant.
            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            (await SeededRoleCountAsync(owner.TenantId, key, cancellationToken)).ShouldBe(1);

            // A re-seed is a no-op for a tenant that already carries the template
            // (the template_key guard): zero newly seeded, still exactly one row.
            var reseeded = await SeedTemplateAsync(admin.Token, key, owner.TenantId, cancellationToken);
            reseeded.ShouldBe(0);
            (await SeededRoleCountAsync(owner.TenantId, key, cancellationToken)).ShouldBe(1);
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    [Fact]
    public async Task Tenant_CanEditAndDelete_ASeededRole_ThroughTheCustomRoleApi()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var key = FreshTemplateKey();

        try
        {
            await CreateTemplateAsync(
                admin.Token,
                new { key, name = "Support", description = "x", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);

            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            var seeded = await FindSeededRoleAsync(owner.Token, key, cancellationToken);
            seeded.ShouldNotBeNull();
            var roleId = seeded.Value.Id;

            // The seeded role is the tenant's own: it may re-permission it...
            var edit = await TenantWorkflow.PatchJsonAsync(
                fixture,
                $"/api/v1/tenant/roles/{roleId}",
                owner.Token,
                new { name = "Support (renamed)", permissions = MembersReadAndNotesWrite },
                cancellationToken);
            edit.StatusCode.ShouldBe(HttpStatusCode.NoContent);

            // ...and delete it.
            var delete = await TenantWorkflow.DeleteAsync(
                fixture, $"/api/v1/tenant/roles/{roleId}", owner.Token, cancellationToken);
            delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

            (await FindSeededRoleAsync(owner.Token, key, cancellationToken)).ShouldBeNull();
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    [Fact]
    public async Task Seeding_ToAnExistingTenant_ProvisionedBeforeTheTemplate_Works()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var key = FreshTemplateKey();

        try
        {
            // The tenant is provisioned BEFORE any template exists, so signup seeds
            // nothing for this template.
            var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            (await FindSeededRoleAsync(owner.Token, key, cancellationToken)).ShouldBeNull();

            // The operator later defines the template and seeds it into the existing
            // tenant - the "apply to existing tenants" path.
            await CreateTemplateAsync(
                admin.Token,
                new { key, name = "Auditor", description = "x", permissions = MembersReadOnly, assignableScopes = TenantScope },
                cancellationToken);

            var seeded = await SeedTemplateAsync(admin.Token, key, owner.TenantId, cancellationToken);
            seeded.ShouldBe(1);

            var role = await FindSeededRoleAsync(owner.Token, key, cancellationToken);
            role.ShouldNotBeNull();
            role.Value.Permissions.ShouldBe(MembersReadOnly);
        }
        finally
        {
            await CleanupTemplateAsync(key, cancellationToken);
        }
    }

    // --- helpers ----------------------------------------------------------

    private static string FreshTemplateKey() => $"tmpl-{Guid.NewGuid():N}";

    private static string FreshPlanKey() => $"plan-{Guid.NewGuid():N}";

    private Task<HttpResponseMessage> CreateTemplateRawAsync(
        string token, object body, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(fixture, "/api/v1/platform/role-templates", token, body, cancellationToken);

    private async Task CreateTemplateAsync(string adminToken, object body, CancellationToken cancellationToken)
    {
        var response = await CreateTemplateRawAsync(adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task<int> SeedTemplateAsync(
        string adminToken, string key, Guid tenantId, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/role-templates/{key}/seed", adminToken, new { tenantId }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("seeded").GetInt32();
    }

    private async Task CreatePlanAsync(string adminToken, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/platform/plans", adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task AssignPlanAsync(
        string adminToken, Guid tenantId, string planKey, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantId}/plan", adminToken, new { plan = planKey }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    /// <summary>
    /// Finds the tenant custom role seeded from <paramref name="templateKey"/> (its
    /// role key equals the template key) via the existing custom-role API, and reads
    /// its permission set. Null when the tenant has no such role.
    /// </summary>
    private async Task<(Guid Id, IReadOnlyList<string> Permissions)?> FindSeededRoleAsync(
        string ownerToken, string templateKey, CancellationToken cancellationToken)
    {
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/roles", ownerToken, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);

        Guid roleId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            var match = doc.RootElement.EnumerateArray()
                .FirstOrDefault(role => role.GetProperty("key").GetString() == templateKey);
            if (match.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            roleId = match.GetProperty("id").GetGuid();
        }

        var detail = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/roles/{roleId}", ownerToken, cancellationToken);
        detail.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var detailDoc = await HttpTestHelpers.ReadJsonAsync(detail, cancellationToken);
        var permissions = detailDoc.RootElement.GetProperty("permissions")
            .EnumerateArray()
            .Select(permission => permission.GetString()!)
            .ToList();
        return (roleId, permissions);
    }

    private Task<long> SeededRoleCountAsync(Guid tenantId, string templateKey, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from tenancy.roles where tenant_id = @tid and template_key = @key",
            cancellationToken,
            ("tid", tenantId),
            ("key", templateKey));

    private Task CleanupTemplateAsync(string key, CancellationToken cancellationToken) =>
        PlatformWorkflow.ExecuteAsync(
            fixture, "delete from platform.role_templates where key = @key", cancellationToken, ("key", key));
}
