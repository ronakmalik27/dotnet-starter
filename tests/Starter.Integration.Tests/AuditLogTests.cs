using System.Net;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The audit log (audit-log.md section 10), driven through the real endpoints and
/// the real projection. Proves: the tenant read is RLS-isolated; the projection is
/// real and idempotent under redelivery; impersonation is audited end to end into
/// the target tenant; platform-admin actions are audited transactionally on the
/// bypass path; the audit:read permission gate; the super-admin cross-tenant read;
/// PII discipline (data is the payload verbatim); catalogue completeness; and the
/// DB-enforced append-only / bypass-only posture.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class AuditLogTests(StarterAppFixture fixture)
{
    // The explicit, named "not audited" set (audit-log.md sections 2, 10): the
    // identity user-activity events (a separate security-events feature) and the
    // null-tenant platform.admin.* events (audited synchronously, not by the async
    // projection). A new event type in neither this set nor the consumer's
    // catalogue fails the completeness test until someone categorizes it.
    private static readonly HashSet<string> NotAudited = new(StringComparer.Ordinal)
    {
        "identity.user.registered",
        "identity.auth_method.linked",
        "identity.password.changed",
        "identity.registration.reattempted",
        "identity.user.verified",
        "identity.session.created",
        "identity.session.revoked",
        "platform.admin.granted",
        "platform.admin.revoked",
        // Plan-catalogue edits are null-tenant operator actions audited
        // synchronously on platform.platform_audit_log (billing-and-entitlements.md
        // section 6), not by the async tenant projection.
        "platform.plan.created",
        "platform.plan.updated",
        // Feature-flag catalogue edits are the same shape (feature-flags.md section
        // 5): null-tenant operator actions audited synchronously on the platform log.
        // The tenant-scoped override events (tenancy.feature_flag.*) ARE on the shared
        // deliverable catalogue, so they are audited by the async projection.
        "platform.feature_flag.created",
        "platform.feature_flag.updated",
    };

    // Hoisted so the repeated helper argument is not a constant array literal (CA1861).
    private static readonly string[] AuditReadOnly = ["audit:read"];

    [Fact]
    public async Task TenantAuditRead_IsRlsIsolated_ToTheCallersTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var ownerA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var noteA = await CreateNoteAsync(ownerA, cancellationToken);
        var noteB = await CreateNoteAsync(ownerB, cancellationToken);

        // Each owner's action lands in their own tenant's audit log.
        (await WaitForAuditCountAsync(ownerA.Token, $"?entity={noteA}", 1, cancellationToken)).ShouldBe(1);
        (await WaitForAuditCountAsync(ownerB.Token, $"?entity={noteB}", 1, cancellationToken)).ShouldBe(1);

        // Neither tenant can ever see the other's row: RLS scopes the read.
        (await AuditCountAsync(ownerA.Token, $"?entity={noteB}", cancellationToken)).ShouldBe(0);
        (await AuditCountAsync(ownerB.Token, $"?entity={noteA}", cancellationToken)).ShouldBe(0);
    }

    [Fact]
    public async Task Projection_IsReal_AndIdempotent_UnderRedelivery()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateNoteAsync(owner, cancellationToken);

        // Exactly one audit row for the source event; its id equals the source
        // domain event id (idempotent projection).
        var eventId = await WaitForAuditEventIdAsync(owner.Token, noteId, cancellationToken);
        (await CountAsync("select count(*) from platform.audit_log where id = @id", cancellationToken, ("id", eventId)))
            .ShouldBe(1);

        // Force a redelivery: null out the fast-lane outbox row so the dispatcher
        // re-claims and re-delivers it.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update platform.outbox set delivered_at = null, next_attempt_at = now() "
            + "where event_id = @id and lane = 'fast'",
            cancellationToken,
            ("id", eventId));

        // The redelivery is handled and re-marked delivered (a pk hit the consumer
        // treats as success), not poisoned...
        await WaitUntilAsync(
            async () => await CountAsync(
                "select count(*) from platform.outbox "
                + "where event_id = @id and lane = 'fast' and delivered_at is not null and poisoned_at is null",
                cancellationToken,
                ("id", eventId)) == 1,
            cancellationToken);

        // ...and it produced no second row.
        (await CountAsync("select count(*) from platform.audit_log where id = @id", cancellationToken, ("id", eventId)))
            .ShouldBe(1);
    }

    [Fact]
    public async Task Impersonation_IsAudited_IntoTheTargetTenant_WithTheOperatorAsActor()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var (_, grantId) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, "Investigating a support ticket.", cancellationToken);

        // The tenant admin (the owner) sees the impersonation-started row in THEIR
        // audit log, with the acting platform admin as the actor.
        var entry = await WaitForAuditEntryAsync(
            owner.Token, $"?action=platform.impersonation.started&entity={grantId}", cancellationToken);
        entry.GetProperty("action").GetString().ShouldBe("platform.impersonation.started");
        entry.GetProperty("entityId").GetGuid().ShouldBe(grantId);
        entry.GetProperty("actorUserId").GetGuid().ShouldBe(admin.UserId);
    }

    [Fact]
    public async Task PlatformActions_AreAudited_Transactionally_OnlyOnTheCommittingBranch()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var candidateToken = await fixture.RegisterVerifyLoginAsync(
            TenantWorkflow.FreshEmail("audit-grant"), TenantWorkflow.Password, cancellationToken);
        var candidateId = HttpTestHelpers.ReadSubject(candidateToken);

        // A genuine grant writes exactly one platform-audit row in the same
        // transaction (no polling: it is synchronous with the grant).
        var grant = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/platform/admins", admin.Token, new { userId = candidateId }, cancellationToken);
        grant.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await GrantedRowCountAsync(candidateId, cancellationToken)).ShouldBe(1);

        // A repeat grant is a no-op (on conflict do nothing): it commits nothing on
        // the audit branch, so there is still exactly one row - the transactional
        // coupling means no audit row without a real, committed action.
        var regrant = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/platform/admins", admin.Token, new { userId = candidateId }, cancellationToken);
        regrant.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await GrantedRowCountAsync(candidateId, cancellationToken)).ShouldBe(1);

        // Revoke (admin remains, so not the last admin) writes the revoked row on
        // its committing branch.
        var revoke = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/platform/admins/{candidateId}", admin.Token, cancellationToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await CountAsync(
            "select count(*) from platform.platform_audit_log "
            + "where action = 'platform.admin.revoked' and subject_user_id = @id",
            cancellationToken,
            ("id", candidateId))).ShouldBe(1);
    }

    [Fact]
    public async Task PermissionGate_Member403_Admin200_AuditorCustomRole_ReadsButNothingElse()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A plain member has no audit:read -> 403 starter:permission-required.
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var memberRead = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/audit", member.Token, cancellationToken);
        memberRead.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(memberRead, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }

        // An admin (audit:read is in the Admin system-role set) succeeds.
        var adminMember = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);
        var adminRead = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/audit", adminMember.Token, cancellationToken);
        adminRead.StatusCode.ShouldBe(HttpStatusCode.OK);

        // A custom "Auditor" role with only audit:read: its holder reads the audit
        // log but is refused an action outside that permission (inviting needs
        // invitations:manage, which the member base role lacks).
        var auditor = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var roleId = await TenantWorkflow.CreateRoleAsync(fixture, owner.Token, "auditor", AuditReadOnly, cancellationToken);
        await TenantWorkflow.AssignRoleAsync(fixture, owner.Token, roleId, auditor.UserId, cancellationToken);

        var auditorRead = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/audit", auditor.Token, cancellationToken);
        auditorRead.StatusCode.ShouldBe(HttpStatusCode.OK);

        var auditorInvite = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/invitations",
            auditor.Token,
            new { email = TenantWorkflow.FreshEmail("nope"), role = "member" },
            cancellationToken);
        auditorInvite.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task SuperAdminRead_CrossesTenants_NarrowsWithTenantFilter_AndRefusesNonAdmin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var ownerA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var noteA = await CreateNoteAsync(ownerA, cancellationToken);
        var noteB = await CreateNoteAsync(ownerB, cancellationToken);

        // Both actions must have projected before the cross-tenant assertions.
        await WaitForAuditCountAsync(ownerA.Token, $"?entity={noteA}", 1, cancellationToken);
        await WaitForAuditCountAsync(ownerB.Token, $"?entity={noteB}", 1, cancellationToken);

        // The super-admin reads across tenants: both tenants' rows are reachable.
        (await PlatformAuditCountAsync(admin.Token, $"?entity={noteA}", cancellationToken)).ShouldBe(1);
        (await PlatformAuditCountAsync(admin.Token, $"?entity={noteB}", cancellationToken)).ShouldBe(1);

        // A tenant filter narrows to one tenant: tenant A's action does not appear
        // when narrowed to tenant B.
        (await PlatformAuditCountAsync(admin.Token, $"?tenant={ownerB.TenantId}&entity={noteA}", cancellationToken))
            .ShouldBe(0);
        (await PlatformAuditCountAsync(admin.Token, $"?tenant={ownerA.TenantId}&entity={noteA}", cancellationToken))
            .ShouldBe(1);

        // A non-admin is refused the platform read.
        var outsider = await fixture.RegisterVerifyLoginAsync(
            TenantWorkflow.FreshEmail("audit-outsider"), TenantWorkflow.Password, cancellationToken);
        var refused = await PlatformWorkflow.GetAsync(fixture, "/api/v1/platform/audit", outsider, cancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(refused, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:platform-admin-required");
    }

    [Fact]
    public async Task PiiDiscipline_ProjectedData_IsTheEventPayloadVerbatim()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateNoteAsync(owner, cancellationToken);
        var eventId = await WaitForAuditEventIdAsync(owner.Token, noteId, cancellationToken);

        // The projected data (jsonb) equals the source domain_events payload
        // (jsonb-equal), so the audit log inherits the spine's "ids and scalars,
        // never PII" discipline rather than re-deriving (or leaking) anything.
        (await CountAsync(
            "select count(*) from platform.audit_log a "
            + "join platform.domain_events d on d.id = a.id "
            + "where a.id = @id and a.data = d.payload",
            cancellationToken,
            ("id", eventId))).ShouldBe(1);
    }

    [Fact]
    public void CatalogueCompleteness_EveryEventType_IsAuditedOrExplicitlyNotAudited()
    {
        // Every event-type string the modules emit, discovered by reflection over
        // the *Events factories (audit-log.md section 10).
        var allEventTypes = DiscoverEventTypes();
        allEventTypes.ShouldNotBeEmpty("the reflection scan must find the event catalogue, or it is vacuous");

        // The projection's subscribed catalogue.
        var consumer = fixture.Factory.Services.GetServices<IDomainEventConsumer>()
            .Single(c => c.GetType().Name == "AuditProjectionConsumer");
        var audited = new HashSet<string>(consumer.EventTypes, StringComparer.Ordinal);

        // A type is never both audited and explicitly not-audited.
        audited.Overlaps(NotAudited).ShouldBeFalse("an event type is audited XOR explicitly not-audited");

        // Every discovered event type is categorized: audited by the projection, or
        // in the named not-audited set. A new event type fails here until someone
        // categorizes it - closing the "silently unaudited" gap.
        var uncategorized = allEventTypes
            .Where(type => !audited.Contains(type) && !NotAudited.Contains(type))
            .ToList();
        uncategorized.ShouldBeEmpty(
            "every event type must be in AuditProjectionConsumer.EventTypes or the named not-audited set");

        // The catalogue and the not-audited set carry no stale entries: every one
        // names a real event type.
        audited.Where(type => !allEventTypes.Contains(type)).ToList()
            .ShouldBeEmpty("AuditProjectionConsumer.EventTypes must not name an event type that does not exist");
        NotAudited.Where(type => !allEventTypes.Contains(type)).ToList()
            .ShouldBeEmpty("the not-audited set must not name an event type that does not exist");
    }

    [Fact]
    public async Task AppendOnly_IsDbEnforced_ForTheRequestRole()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // Seed one tenant audit row on the admin (superuser) connection, which
        // bypasses RLS and privilege.
        var tenantId = Guid.CreateVersion7();
        var rowId = Guid.CreateVersion7();
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into platform.audit_log "
            + "(id, tenant_id, occurred_at, recorded_at, action, actor_user_id, entity_id, summary, data) "
            + "values (@id, @tenant, now(), now(), 'test.seed', null, null, 'seed', '{}'::jsonb)",
            cancellationToken,
            ("id", rowId),
            ("tenant", tenantId));

        // The request role (starter_app) can no longer UPDATE the tenant audit log:
        // Postgres rejects it (insufficient privilege), not merely the absence of
        // an API. The tenant GUC is set so the row is visible under RLS, isolating
        // the privilege check as the reason.
        var update = await RequestRoleThrowsAsync(
            "update platform.audit_log set summary = 'tampered' where id = @id",
            tenantId,
            cancellationToken,
            ("id", rowId));
        update.SqlState.ShouldBe(PostgresErrorCodes.InsufficientPrivilege);

        // Nor DELETE it.
        var delete = await RequestRoleThrowsAsync(
            "delete from platform.audit_log where id = @id",
            tenantId,
            cancellationToken,
            ("id", rowId));
        delete.SqlState.ShouldBe(PostgresErrorCodes.InsufficientPrivilege);

        // And the request role cannot read platform.platform_audit_log at all
        // (REVOKE ALL): it can neither see nor forge the platform audit trail.
        var read = await RequestRoleThrowsAsync(
            "select count(*) from platform.platform_audit_log", guc: null, cancellationToken);
        read.SqlState.ShouldBe(PostgresErrorCodes.InsufficientPrivilege);
    }

    // --- discovery -------------------------------------------------------

    private static HashSet<string> DiscoverEventTypes()
    {
        // A fixed, valid instant for the DateTimeOffset factory args (UUIDv7 minting
        // rejects a pre-1970 timestamp, so default(DateTimeOffset) will not do).
        var instant = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var eventTypes = new HashSet<string>(StringComparer.Ordinal);
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(assembly => assembly.GetName().Name is { } name
                && name.StartsWith("Starter.", StringComparison.Ordinal)
                && !name.Contains(".Tests", StringComparison.Ordinal));

        foreach (var assembly in assemblies)
        {
            foreach (var type in assembly.GetTypes()
                .Where(type => type.Name.EndsWith("Events", StringComparison.Ordinal)))
            {
                var factories = type
                    .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                    .Where(method => method.ReturnType == typeof(DomainEventRecord));

                foreach (var factory in factories)
                {
                    var arguments = factory.GetParameters()
                        .Select(parameter => DefaultArgument(parameter.ParameterType, instant))
                        .ToArray();
                    var record = (DomainEventRecord)factory.Invoke(null, arguments)!;
                    eventTypes.Add(record.EventType);
                }
            }
        }

        return eventTypes;
    }

    private static object? DefaultArgument(Type type, DateTimeOffset instant)
    {
        if (type == typeof(DateTimeOffset))
        {
            return instant;
        }

        // A non-nullable value type gets its zero value; a reference type or a
        // Nullable<T> gets null. The EventType is a constant literal in the
        // factory, so the actual argument values never affect it.
        return type.IsValueType && Nullable.GetUnderlyingType(type) is null
            ? Activator.CreateInstance(type)
            : null;
    }

    // --- HTTP helpers ----------------------------------------------------

    private async Task<Guid> CreateNoteAsync(OwnerContext owner, CancellationToken cancellationToken)
    {
        var create = await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Audited note", cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<int> AuditCountAsync(string token, string query, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/audit" + query, token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("items").GetArrayLength();
    }

    private async Task<int> PlatformAuditCountAsync(string token, string query, CancellationToken cancellationToken)
    {
        var response = await PlatformWorkflow.GetAsync(fixture, "/api/v1/platform/audit" + query, token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("items").GetArrayLength();
    }

    private async Task<int> WaitForAuditCountAsync(
        string token, string query, int atLeast, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var count = await AuditCountAsync(token, query, cancellationToken);
            if (count >= atLeast)
            {
                return count;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No audit row for '{query}' appeared within the deadline.");
    }

    private async Task<Guid> WaitForAuditEventIdAsync(string token, Guid noteId, CancellationToken cancellationToken)
    {
        var entry = await WaitForAuditEntryAsync(token, $"?entity={noteId}", cancellationToken);
        return entry.GetProperty("id").GetGuid();
    }

    private async Task<JsonElement> WaitForAuditEntryAsync(
        string token, string query, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(
                fixture, "/api/v1/tenant/audit" + query, token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            var items = doc.RootElement.GetProperty("items");
            if (items.GetArrayLength() > 0)
            {
                // Clone so the element outlives the JsonDocument's using scope.
                return items[0].Clone();
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No audit entry for '{query}' appeared within the deadline.");
    }

    // --- SQL helpers -----------------------------------------------------

    private Task<int> GrantedRowCountAsync(Guid subjectUserId, CancellationToken cancellationToken) =>
        CountAsync(
            "select count(*) from platform.platform_audit_log "
            + "where action = 'platform.admin.granted' and subject_user_id = @id",
            cancellationToken,
            ("id", subjectUserId));

    private async Task<int> CountAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters) =>
        (int)await PlatformWorkflow.CountAsync(fixture, sql, cancellationToken, parameters);

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException("The awaited condition did not hold within the deadline.");
    }

    private async Task<PostgresException> RequestRoleThrowsAsync(
        string sql, Guid? guc, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.RequestDataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        if (guc is Guid tenant)
        {
            await using var setTenant = new NpgsqlCommand(
                "select set_config('app.current_tenant', @tenant, true)", connection, transaction);
            setTenant.Parameters.AddWithValue("tenant", tenant.ToString());
            await setTenant.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return await Should.ThrowAsync<PostgresException>(
            async () => await command.ExecuteScalarAsync(cancellationToken));
    }
}
