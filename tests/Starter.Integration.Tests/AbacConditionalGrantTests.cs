using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Auth;
using Starter.Platform.Auth.Conditions;
using Starter.Platform.Tenancy;
using Starter.Tenancy;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The ABAC conditional-grant seam (abac.md section 10), driven through the real
/// endpoints, the DI-resolved resolvers, and the RLS-bound database. Proves:
/// <list type="bullet">
///   <item>the SAFETY HINGE - Tier 1 (<c>GetCallerPermissionsAsync</c>) excludes a
///   conditional grant from the cached effective set on ALL FOUR grant queries
///   (tenant/workspace x user/service-account), asserted DIRECTLY on the set, while
///   a companion unconditional grant still resolves and the gated endpoint 403s;</item>
///   <item>Tier 2 evaluates LIVE and never memoizes the decision - the same
///   <c>ip_cidr</c> grant flips true/false across two calls in one scope as the
///   client IP changes, and a <c>time_of_day</c> grant flips as the request instant
///   changes;</item>
///   <item>the fail-closed matrix - an unknown condition type, a missing client IP,
///   and a suspended member all deny;</item>
///   <item>the grant path - a malformed condition is a 422 that writes no row, and a
///   valid condition round-trips through ListAssignments and the DSAR export;</item>
///   <item>a service-account <c>ip_cidr</c> grant confines the key to the range;</item>
///   <item>cross-tenant invisibility (RLS).</item>
/// </list>
/// The client IP and clock cannot be varied over the in-process TestServer, so the
/// live-evaluation, fail-closed, and service-account-confinement cases drive the
/// resolver directly with hand-built <see cref="RequestAttributes"/> (abac.md
/// section 10 sanctions this; the pure evaluator logic is unit-tested in
/// Starter.Platform.Tests).
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class AbacConditionalGrantTests(StarterAppFixture fixture)
{
    private const string TenantUserPermission = "invitations:manage";
    private const string WorkspaceUserPermission = "settings:manage";
    private const string TenantServiceAccountPermission = "webhooks:manage";
    private const string WorkspaceServiceAccountPermission = "audit:read";
    private const string CompanionPermission = "members:manage";

    private const string InRangeIp = "203.0.113.7";
    private const string OutOfRangeIp = "198.51.100.7";

    // Hoisted so the CreateRole helper argument is not a constant array literal (CA1861).
    private static readonly string[] TenantUserPerm = [TenantUserPermission];
    private static readonly string[] WorkspaceUserPerm = [WorkspaceUserPermission];
    private static readonly string[] TenantServiceAccountPerm = [TenantServiceAccountPermission];
    private static readonly string[] WorkspaceServiceAccountPerm = [WorkspaceServiceAccountPermission];
    private static readonly string[] CompanionPerm = [CompanionPermission];
    private static readonly string[] FlipPerm = [TenantUserPermission];

    private static readonly DateTimeOffset Midday = new(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

    private static object IpCidrCondition => new { type = "ip_cidr", allow = new[] { "203.0.113.0/24" } };

    // --- The safety hinge: Tier 1 excludes conditional grants (headline) -----

    [Fact]
    public async Task Tier1_ExcludesConditionalGrants_AcrossAllFourPaths()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var (serviceAccountId, _) = await CreateServiceAccountAsync(owner, cancellationToken);
        var workspaceId = await TenantWorkflow.CreateWorkspaceAsync(
            fixture, owner.Token, TenantWorkflow.FreshSlug(), "Prod", cancellationToken);

        // One conditional grant per path, each with a DISTINCT permission granted at
        // exactly one (scope, principal), so each assertion isolates one of the four
        // "condition IS NULL" filters. Assignable "both" so a tenant-owned role can be
        // granted at tenant OR workspace scope.
        var tenantUserRole = await CreateRole(owner, "cond-tenant-user", TenantUserPerm, cancellationToken);
        var workspaceUserRole = await CreateRole(owner, "cond-ws-user", WorkspaceUserPerm, cancellationToken);
        var tenantSaRole = await CreateRole(owner, "cond-tenant-sa", TenantServiceAccountPerm, cancellationToken);
        var workspaceSaRole = await CreateRole(owner, "cond-ws-sa", WorkspaceServiceAccountPerm, cancellationToken);
        var companionRole = await CreateRole(owner, "uncond-companion", CompanionPerm, cancellationToken);

        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId = tenantUserRole, userId = member.UserId, condition = IpCidrCondition }, cancellationToken);
        await AssignAsync(owner.Token, $"/api/v1/workspaces/{workspaceId}/role-assignments",
            new { roleId = workspaceUserRole, userId = member.UserId, condition = IpCidrCondition }, cancellationToken);
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId = tenantSaRole, serviceAccountId, condition = IpCidrCondition }, cancellationToken);
        await AssignAsync(owner.Token, $"/api/v1/workspaces/{workspaceId}/role-assignments",
            new { roleId = workspaceSaRole, serviceAccountId, condition = IpCidrCondition }, cancellationToken);
        // The companion is UNCONDITIONAL, so it must resolve into the cached set.
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId = companionRole, userId = member.UserId }, cancellationToken);

        // Assert the cached set DIRECTLY for each of the four paths.
        var tenantUser = await ResolvePermissionsAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, workspaceId: null, cancellationToken);
        tenantUser.ShouldNotContain(TenantUserPermission);
        tenantUser.ShouldContain(CompanionPermission);

        var workspaceUser = await ResolvePermissionsAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, workspaceId, cancellationToken);
        workspaceUser.ShouldNotContain(WorkspaceUserPermission);

        var tenantServiceAccount = await ResolvePermissionsAsync(
            owner.TenantId, serviceAccountId, PrincipalTypes.ServiceAccount, workspaceId: null, cancellationToken);
        tenantServiceAccount.ShouldNotContain(TenantServiceAccountPermission);

        var workspaceServiceAccount = await ResolvePermissionsAsync(
            owner.TenantId, serviceAccountId, PrincipalTypes.ServiceAccount, workspaceId, cancellationToken);
        workspaceServiceAccount.ShouldNotContain(WorkspaceServiceAccountPermission);

        // And the gate 403s: over HTTP the TestServer's client IP is not in the CIDR,
        // so the conditional invitations:manage grant confers nothing - it is not
        // silently always-on.
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            member.Token,
            new { email = TenantWorkflow.FreshEmail("invitee"), role = "member" },
            cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var problem = await HttpTestHelpers.ReadJsonAsync(invite, cancellationToken);
        problem.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    // --- Tier 2 evaluates live and never memoizes the decision ---------------

    [Fact]
    public async Task Tier2_IpCidrGrant_FlipsAcrossRequests_WithoutCachingTheDecision()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await CreateRole(owner, "ip-flip", FlipPerm, cancellationToken);
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId, userId = member.UserId, condition = IpCidrCondition }, cancellationToken);

        // Two calls in ONE scope (so the resolver reuses its loaded rows) with
        // different client IPs must yield different decisions - proving the rows may
        // be cached but the DECISION is re-evaluated every call (abac.md section 5).
        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().Resolve(owner.TenantId, slug: null);
        var resolver = scope.ServiceProvider.GetRequiredService<IConditionalGrantResolver>();

        var inRange = Attributes(InRangeIp);
        var outOfRange = Attributes(OutOfRangeIp);

        (await resolver.IsGrantedAsync(
            member.UserId, PrincipalTypes.User, TenantUserPermission, inRange, null, cancellationToken))
            .ShouldBeTrue();
        (await resolver.IsGrantedAsync(
            member.UserId, PrincipalTypes.User, TenantUserPermission, outOfRange, null, cancellationToken))
            .ShouldBeFalse();
    }

    [Fact]
    public async Task Tier2_TimeOfDayGrant_FlipsInsideAndOutsideTheWindow()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await CreateRole(owner, "time-flip", FlipPerm, cancellationToken);
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new
            {
                roleId,
                userId = member.UserId,
                condition = new { type = "time_of_day", startUtc = "09:00", endUtc = "17:00" },
            },
            cancellationToken);

        var inside = new RequestAttributes { Now = Midday, ClientIp = null };
        var outside = new RequestAttributes
        {
            Now = new DateTimeOffset(2026, 7, 23, 20, 0, 0, TimeSpan.Zero),
            ClientIp = null,
        };

        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission, inside, null, cancellationToken))
            .ShouldBeTrue();
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission, outside, null, cancellationToken))
            .ShouldBeFalse();
    }

    // --- Fail-closed matrix --------------------------------------------------

    [Fact]
    public async Task Tier2_FailsClosed_OnMissingClientIpAndUnknownConditionType()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await CreateRole(owner, "fail-closed", FlipPerm, cancellationToken);
        var assignmentId = await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId, userId = member.UserId, condition = IpCidrCondition }, cancellationToken);

        // A well-formed, in-range request is granted (sanity).
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeTrue();

        // No resolvable client IP denies an ip_cidr grant.
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission,
            new RequestAttributes { Now = Midday, ClientIp = null }, null, cancellationToken)).ShouldBeFalse();

        // Force an unknown condition type into the stored row (write-time validation
        // would never let one through), then a fresh scope reloads and must deny.
        await SetConditionAsync(assignmentId, """{"type": "mystery"}""", cancellationToken);
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeFalse();
    }

    [Fact]
    public async Task Tier2_FailsClosed_WhenMemberIsSuspended()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var roleId = await CreateRole(owner, "suspend-check", FlipPerm, cancellationToken);
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId, userId = member.UserId, condition = IpCidrCondition }, cancellationToken);

        // Active + in-range: granted.
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeTrue();

        // Suspending the membership makes the same in-range request deny: the
        // conditional resolver applies the SAME active-membership gate, so a
        // suspended member reaches no conditional grant.
        await SuspendMembershipAsync(owner.TenantId, member.UserId, cancellationToken);
        (await IsGrantedAsync(
            owner.TenantId, member.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeFalse();
    }

    // --- Service account confinement -----------------------------------------

    [Fact]
    public async Task Tier2_ServiceAccountIpCidrGrant_ConfinesToTheRange()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var (serviceAccountId, _) = await CreateServiceAccountAsync(owner, cancellationToken);

        var roleId = await CreateRole(owner, "sa-confined", TenantServiceAccountPerm, cancellationToken);
        await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId, serviceAccountId, condition = IpCidrCondition }, cancellationToken);

        (await IsGrantedAsync(
            owner.TenantId, serviceAccountId, PrincipalTypes.ServiceAccount, TenantServiceAccountPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeTrue();
        (await IsGrantedAsync(
            owner.TenantId, serviceAccountId, PrincipalTypes.ServiceAccount, TenantServiceAccountPermission,
            Attributes(OutOfRangeIp), null, cancellationToken)).ShouldBeFalse();
    }

    // --- Grant path: validation, round-trip, DSAR ----------------------------

    [Fact]
    public async Task GrantPath_MalformedCondition_Is422AndWritesNoRow()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var roleId = await CreateRole(owner, "bad-cond", FlipPerm, cancellationToken);

        // A bad CIDR and an unknown type are both rejected at write time.
        foreach (var condition in new object[]
        {
            new { type = "ip_cidr", allow = new[] { "not-a-cidr" } },
            new { type = "mystery" },
        })
        {
            var response = await TenantWorkflow.PostJsonAsync(
                fixture,
                "/api/v1/tenant/role-assignments",
                owner.Token,
                new { roleId, userId = owner.UserId, condition },
                cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
            using var problem = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            problem.RootElement.GetProperty("type").GetString().ShouldBe("starter:validation");
        }

        // No assignment for that role was written.
        var list = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/role-assignments", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken);
        doc.RootElement.EnumerateArray()
            .Any(item => item.GetProperty("roleId").GetGuid() == roleId)
            .ShouldBeFalse();
    }

    [Fact]
    public async Task GrantPath_ValidCondition_RoundTripsThroughListAndDsarExport()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var roleId = await CreateRole(owner, "round-trip", FlipPerm, cancellationToken);
        var assignmentId = await AssignAsync(owner.Token, "/api/v1/tenant/role-assignments",
            new { roleId, userId = owner.UserId, condition = IpCidrCondition }, cancellationToken);

        // The listing surfaces the condition as a JSON object the admin plane can render.
        var list = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/role-assignments", owner.Token, cancellationToken);
        using var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken);
        var assignment = doc.RootElement.EnumerateArray()
            .Single(item => item.GetProperty("id").GetGuid() == assignmentId);
        var condition = assignment.GetProperty("condition");
        condition.ValueKind.ShouldBe(JsonValueKind.Object);
        condition.GetProperty("type").GetString().ShouldBe("ip_cidr");
        condition.GetProperty("allow").EnumerateArray().Select(e => e.GetString())
            .ShouldContain("203.0.113.0/24");

        // The DSAR export carries the condition (tenant policy, not a secret).
        var export = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/export", owner.Token, cancellationToken);
        export.StatusCode.ShouldBe(HttpStatusCode.OK);
        var bundle = await export.Content.ReadAsStringAsync(cancellationToken);
        bundle.ShouldContain("ip_cidr");
        bundle.ShouldContain("203.0.113.0/24");
    }

    // --- Cross-tenant invisibility -------------------------------------------

    [Fact]
    public async Task ConditionalGrant_IsInvisibleToAnotherTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var memberA = await TenantWorkflow.InviteAcceptMintAsync(fixture, tenantA, "member", cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var roleId = await CreateRole(tenantA, "cross-tenant", FlipPerm, cancellationToken);
        await AssignAsync(tenantA.Token, "/api/v1/tenant/role-assignments",
            new { roleId, userId = memberA.UserId, condition = IpCidrCondition }, cancellationToken);

        // Under tenant A's boundary the in-range request is granted.
        (await IsGrantedAsync(
            tenantA.TenantId, memberA.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeTrue();

        // Under tenant B's boundary the same grant is invisible (RLS), so it denies.
        (await IsGrantedAsync(
            tenantB.TenantId, memberA.UserId, PrincipalTypes.User, TenantUserPermission,
            Attributes(InRangeIp), null, cancellationToken)).ShouldBeFalse();
    }

    // --- Helpers -------------------------------------------------------------

    private static RequestAttributes Attributes(string clientIp) => new()
    {
        Now = Midday,
        ClientIp = IPAddress.Parse(clientIp),
    };

    private Task<Guid> CreateRole(
        OwnerContext owner, string key, IReadOnlyCollection<string> permissions, CancellationToken cancellationToken) =>
        // "both" so a tenant-owned role can be granted at tenant OR workspace scope.
        TenantWorkflow.CreateRoleAsync(fixture, owner.Token, key, "both", permissions, cancellationToken);

    private async Task<Guid> AssignAsync(
        string bearer, string uri, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(fixture, uri, bearer, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<(Guid Id, string Key)> CreateServiceAccountAsync(
        OwnerContext owner, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/service-accounts",
            owner.Token,
            new { name = $"bot-{Guid.NewGuid():N}" },
            cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (doc.RootElement.GetProperty("id").GetGuid(), doc.RootElement.GetProperty("key").GetString()!);
    }

    private async Task<IReadOnlySet<string>> ResolvePermissionsAsync(
        Guid tenantId, Guid principalId, string principalType, Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().Resolve(tenantId, slug: null);
        var tenancy = scope.ServiceProvider.GetRequiredService<ITenancyApi>();
        return workspaceId is Guid workspace
            ? await tenancy.GetCallerPermissionsAsync(principalId, workspace, principalType, cancellationToken)
            : await tenancy.GetCallerPermissionsAsync(principalId, principalType, cancellationToken);
    }

    private async Task<bool> IsGrantedAsync(
        Guid tenantId,
        Guid principalId,
        string principalType,
        string permission,
        RequestAttributes attributes,
        Guid? workspaceId,
        CancellationToken cancellationToken)
    {
        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().Resolve(tenantId, slug: null);
        var resolver = scope.ServiceProvider.GetRequiredService<IConditionalGrantResolver>();
        return await resolver.IsGrantedAsync(
            principalId, principalType, permission, attributes, workspaceId, cancellationToken);
    }

    private async Task SetConditionAsync(Guid assignmentId, string conditionJson, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "update tenancy.role_assignments set condition = @condition::jsonb where id = @id", connection);
        command.Parameters.AddWithValue("condition", conditionJson);
        command.Parameters.AddWithValue("id", assignmentId);
        (await command.ExecuteNonQueryAsync(cancellationToken)).ShouldBe(1);
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
