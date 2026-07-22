using System.Net;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Billing, plans, and entitlements (billing-and-entitlements.md section 10),
/// driven through the real endpoints and the real seeded plan catalogue. Proves:
/// entitlements FAIL OPEN on the seeded default plan; gating bites on a restrictive
/// plan (402); the entitlement gate is orthogonal to the permission gate (402 vs
/// 403); plan assignment drives the seat limit; plan CRUD and assign are
/// super-admin only; entitlement resolution is RLS-isolated per tenant; the plan
/// permission-catalogue gate (permission_not_in_plan); provisioning follows the
/// is_default plan and the exactly-one-default index holds; seatLimit is required
/// at plan-write time; and plan create/update/assign are audited.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class BillingEntitlementsTests(StarterAppFixture fixture)
{
    private const string WebhooksPath = "/api/v1/tenant/webhooks";

    private static readonly string[] NotesFeatureOnly = ["notes"];

    private static readonly string[] MembersReadOnly = ["members:read"];

    private static readonly string[] RolesManagePermission = ["roles:manage"];

    // --- Fail open by default ---------------------------------------------

    [Fact]
    public async Task FailOpen_DefaultPlan_PassesEveryGatedFeature()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // The tenant is on the seeded free plan (features NULL = unrestricted), so
        // the webhook entitlement gate is a no-op: the owner (who holds
        // webhooks:manage) reaches the endpoint just as before billing shipped.
        var list = await TenantWorkflow.GetAsync(fixture, WebhooksPath, owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);

        // The seats view reports the plan and its limits.
        var seats = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/seats", owner.Token, cancellationToken);
        seats.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(seats, cancellationToken);
        doc.RootElement.GetProperty("plan").GetString().ShouldBe("free");
        doc.RootElement.GetProperty("seatLimit").GetInt32().ShouldBe(5);
        doc.RootElement.GetProperty("limits").GetProperty("seatLimit").GetInt32().ShouldBe(5);
    }

    // --- Gating bites on a restrictive plan -------------------------------

    [Fact]
    public async Task Gating_BitesOnRestrictivePlan_ButNotOnUnrestrictedPlan()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var restricted = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var unrestricted = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // An operator publishes a plan whose features omit webhooks, and assigns it
        // to one tenant.
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "No webhooks", features = NotesFeatureOnly, limits = new { seatLimit = 5 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, restricted.TenantId, planKey, cancellationToken);

        // The restricted tenant's webhook calls now get 402 payment-required...
        var blocked = await TenantWorkflow.GetAsync(fixture, WebhooksPath, restricted.Token, cancellationToken);
        blocked.StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(blocked, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:payment-required");
        }

        // ...while a tenant on the unrestricted (free) plan still succeeds.
        var allowed = await TenantWorkflow.GetAsync(fixture, WebhooksPath, unrestricted.Token, cancellationToken);
        allowed.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // --- Entitlement is orthogonal to permission --------------------------

    [Fact]
    public async Task Entitlement_IsOrthogonalTo_Permission_402VersusForbidden()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A caller WITH webhooks:manage (the owner) but on a plan that omits the
        // webhooks feature is 402 (not 403): the permission is present, the
        // entitlement is not.
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "No webhooks", features = NotesFeatureOnly, limits = new { seatLimit = 5 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

        var entitlementBlocked = await TenantWorkflow.GetAsync(fixture, WebhooksPath, owner.Token, cancellationToken);
        entitlementBlocked.StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);

        // A caller on the unrestricted (free) plan WITHOUT the permission (a plain
        // member) is 403 (not 402): RequirePermission composes BEFORE
        // RequireEntitlement, so the missing permission wins and the paywalled
        // feature is never revealed.
        var freeOwner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, freeOwner, "member", cancellationToken);
        var permissionBlocked = await TenantWorkflow.GetAsync(fixture, WebhooksPath, member.Token, cancellationToken);
        permissionBlocked.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(permissionBlocked, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
    }

    // --- Plan assignment drives the seat limit ----------------------------

    [Fact]
    public async Task PlanAssignment_DrivesSeatLimit_AndTheSeatCheckThenRefuses()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Assign a plan with seatLimit = 2, denormalizing it onto the tenant row.
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Two seats", limits = new { seatLimit = 2 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);

        var seats = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/seats", owner.Token, cancellationToken);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(seats, cancellationToken))
        {
            doc.RootElement.GetProperty("seatLimit").GetInt32().ShouldBe(2);
            doc.RootElement.GetProperty("plan").GetString().ShouldBe(planKey);
        }

        // The owner is seat 1. Accepting a second member fills seat 2 (1 < 2)...
        var second = await InviteRegisterAndAcceptAsync(owner, "member", cancellationToken);
        second.StatusCode.ShouldBe(HttpStatusCode.OK);

        // ...and the third accept is refused by the (unchanged) race-proof seat
        // check reading the plan-derived seat_limit off the locked tenant row.
        var third = await InviteRegisterAndAcceptAsync(owner, "member", cancellationToken);
        third.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        using var conflict = await HttpTestHelpers.ReadJsonAsync(third, cancellationToken);
        conflict.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-seat-limit-reached");
    }

    // --- Super-admin only -------------------------------------------------

    [Fact]
    public async Task PlanCrudAndAssign_AreSuperAdminOnly()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A tenant owner (not a platform admin) cannot create a plan...
        var create = await CreatePlanRawAsync(
            owner.Token,
            new { key = FreshPlanKey(), name = "Nope", limits = new { seatLimit = 5 } },
            cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-admin-required");
        }

        // ...nor change its own tenant's plan (there is no tenant-facing assign
        // path; the platform assign requires a platform admin).
        var assign = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{owner.TenantId}/plan", owner.Token, new { plan = "free" }, cancellationToken);
        assign.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    // --- RLS isolation of entitlement resolution --------------------------

    [Fact]
    public async Task EntitlementResolution_IsRlsIsolated_PerTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var tenantA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var tenantB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A plan change to tenant A never affects tenant B's resolution: each
        // GetCallerEntitlementsAsync reads only the caller's OWN tenant plan.
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "No webhooks", features = NotesFeatureOnly, limits = new { seatLimit = 5 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, tenantA.TenantId, planKey, cancellationToken);

        (await TenantWorkflow.GetAsync(fixture, WebhooksPath, tenantA.Token, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);
        (await TenantWorkflow.GetAsync(fixture, WebhooksPath, tenantB.Token, cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // --- Permission catalogue is plan-gated -------------------------------

    [Fact]
    public async Task PermissionCatalogue_IsPlanGated_ButUnrestrictedByDefault()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // On the default (NULL permissions) plan, authoring a role that includes
        // roles:manage succeeds - the gate is fail-open.
        var freeOwner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var onDefault = await AuthorRoleAsync(freeOwner.Token, "auth-default", RolesManagePermission, cancellationToken);
        onDefault.StatusCode.ShouldBe(HttpStatusCode.Created);

        // On a plan whose permissions list omits roles:manage, the same authoring is
        // refused with the plan-upgrade answer (permission_not_in_plan -> 402).
        var gatedOwner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Members only", permissions = MembersReadOnly, limits = new { seatLimit = 5 } },
            cancellationToken);
        await AssignPlanAsync(admin.Token, gatedOwner.TenantId, planKey, cancellationToken);

        var refused = await AuthorRoleAsync(gatedOwner.Token, "auth-gated", RolesManagePermission, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);
        using var doc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:payment-required");

        // A permission the plan DOES include stays grantable.
        var allowed = await AuthorRoleAsync(gatedOwner.Token, "auth-ok", MembersReadOnly, cancellationToken);
        allowed.StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    // --- Provisioning follows the default plan ----------------------------

    [Fact]
    public async Task Provisioning_FollowsTheDefaultPlan_AndSecondDefaultIsRejected()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // With `free` seeded default, a new tenant lands on free / 5.
        var first = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await AssertPlanAndSeatLimitAsync(first.Token, "free", 5, cancellationToken);

        var newDefault = FreshPlanKey();
        try
        {
            // Promote a new default plan (demoting free atomically): the next new
            // tenant now lands on it.
            await CreatePlanAsync(
                admin.Token,
                new { key = newDefault, name = "Pro", limits = new { seatLimit = 9 }, isDefault = true },
                cancellationToken);

            var second = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
            await AssertPlanAndSeatLimitAsync(second.Token, newDefault, 9, cancellationToken);

            // A second is_default = true write is rejected by the partial unique
            // index (a raw insert of another default row, bypassing the atomic
            // demote the API does).
            await Should.ThrowAsync<PostgresException>(async () =>
                await PlatformWorkflow.ExecuteAsync(
                    fixture,
                    "insert into platform.plans (key, name, features, permissions, limits, is_default, created_at, updated_at) "
                    + "values (@key, 'Second default', null, null, '{\"seatLimit\": 3}'::jsonb, true, now(), now())",
                    cancellationToken,
                    ("key", FreshPlanKey())));
        }
        finally
        {
            // Restore `free` as the default so the shared collection's other tests
            // keep provisioning onto free / 5.
            await PatchPlanAsync(admin.Token, "free", new { isDefault = true }, cancellationToken);
        }
    }

    // --- seatLimit is required at plan-write time -------------------------

    [Fact]
    public async Task SeatLimit_IsRequired_AtPlanWriteTime()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);

        // limits omitting seatLimit is refused...
        var missing = await CreatePlanRawAsync(
            admin.Token,
            new { key = FreshPlanKey(), name = "No seat limit", limits = new { maxWorkspaces = 3 } },
            cancellationToken);
        missing.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // ...and a non-positive seatLimit is refused too.
        var nonPositive = await CreatePlanRawAsync(
            admin.Token,
            new { key = FreshPlanKey(), name = "Zero seats", limits = new { seatLimit = 0 } },
            cancellationToken);
        nonPositive.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    // --- Audited ----------------------------------------------------------

    [Fact]
    public async Task PlanCreateUpdate_AreAuditedOnThePlatformLog_AndAssignOnTheTenantLog()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var planKey = FreshPlanKey();
        await CreatePlanAsync(
            admin.Token,
            new { key = planKey, name = "Audited", limits = new { seatLimit = 5 } },
            cancellationToken);
        await PatchPlanAsync(admin.Token, planKey, new { name = "Audited (renamed)" }, cancellationToken);

        // Plan create and update each land a platform-audit row synchronously.
        (await PlatformAuditCountAsync("platform.plan.created", cancellationToken)).ShouldBeGreaterThanOrEqualTo(1);
        (await PlatformAuditCountAsync("platform.plan.updated", cancellationToken)).ShouldBeGreaterThanOrEqualTo(1);

        // Assigning the plan to a tenant lands a tenant audit row (and is
        // webhook-deliverable - both ride the shared deliverable-event catalogue).
        await AssignPlanAsync(admin.Token, owner.TenantId, planKey, cancellationToken);
        await WaitForTenantAuditAsync(owner.Token, "tenancy.tenant.plan_changed", cancellationToken);
    }

    // --- helpers ----------------------------------------------------------

    private static string FreshPlanKey() => $"plan-{Guid.NewGuid():N}";

    private Task<HttpResponseMessage> CreatePlanRawAsync(string token, object body, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(fixture, "/api/v1/platform/plans", token, body, cancellationToken);

    private async Task CreatePlanAsync(string adminToken, object body, CancellationToken cancellationToken)
    {
        var response = await CreatePlanRawAsync(adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task PatchPlanAsync(string adminToken, string key, object body, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/platform/plans/{key}", adminToken, body, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private async Task AssignPlanAsync(
        string adminToken, Guid tenantId, string planKey, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/tenants/{tenantId}/plan", adminToken, new { plan = planKey }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private Task<HttpResponseMessage> AuthorRoleAsync(
        string token, string key, IReadOnlyList<string> permissions, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/roles",
            token,
            new { key, name = key, assignableAt = "tenant", permissions },
            cancellationToken);

    private async Task AssertPlanAndSeatLimitAsync(
        string token, string plan, int seatLimit, CancellationToken cancellationToken)
    {
        var seats = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/seats", token, cancellationToken);
        seats.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(seats, cancellationToken);
        doc.RootElement.GetProperty("plan").GetString().ShouldBe(plan);
        doc.RootElement.GetProperty("seatLimit").GetInt32().ShouldBe(seatLimit);
    }

    private async Task<HttpResponseMessage> InviteRegisterAndAcceptAsync(
        OwnerContext owner, string role, CancellationToken cancellationToken)
    {
        var email = TenantWorkflow.FreshEmail(role);
        var inviteeToken = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);

        var invite = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/invitations", owner.Token, new { email, role }, cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var invitationEmail = fixture.Emails.Sent.Last(
            message => message.To == email && message.Subject.Contains("invited", StringComparison.Ordinal));
        var rawToken = HttpTestHelpers.ExtractVerificationToken(invitationEmail);

        return await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
    }

    private Task<long> PlatformAuditCountAsync(string action, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.platform_audit_log where action = @action",
            cancellationToken,
            ("action", action));

    private async Task WaitForTenantAuditAsync(string token, string action, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(
                fixture, $"/api/v1/tenant/audit?action={action}", token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            if (doc.RootElement.GetProperty("items").GetArrayLength() > 0)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No tenant audit row for '{action}' appeared within the deadline.");
    }
}
