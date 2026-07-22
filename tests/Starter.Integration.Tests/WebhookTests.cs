using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Webhooks;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Outbound webhooks (webhooks.md section 11), driven through the real endpoints, the
/// real fan-out consumer, and the real leader-elected delivery worker. Proves: fan-out is
/// real and idempotent; RLS isolation of endpoints and deliveries; a signed delivery whose
/// signature verifies against the (encrypted-at-rest) secret; retry and dead-letter with a
/// healthy sibling still delivering exactly once; replay; secret shown once and stored
/// encrypted; the SSRF guard (register-time and connect-time, including DNS rebinding); and
/// that endpoint lifecycle is audited.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class WebhookTests(StarterAppFixture fixture)
{
    private const string NoteEvent = "sample.note.created";

    private static readonly string[] NoteSubscription = [NoteEvent];

    [Fact]
    public async Task Fanout_IsReal_AndIdempotent_UnderRedelivery()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Two subscribed endpoints, one subscribed to a different type, and one disabled.
        var (subscribedA, _) = await InsertEndpointAsync(owner.TenantId, DeadUrl(), NoteSubscription, disabled: false, cancellationToken);
        var (subscribedB, _) = await InsertEndpointAsync(owner.TenantId, DeadUrl(), NoteSubscription, disabled: false, cancellationToken);
        var (otherType, _) = await InsertEndpointAsync(owner.TenantId, DeadUrl(), ["sample.widget.created"], disabled: false, cancellationToken);
        var (disabled, _) = await InsertEndpointAsync(owner.TenantId, DeadUrl(), NoteSubscription, disabled: true, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Fan out", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        // Two delivery rows, one per subscribed endpoint; none for the non-subscribing or
        // disabled endpoint.
        await WaitUntilAsync(async () => await CountDeliveriesAsync(subscribedA, cancellationToken) == 1, cancellationToken);
        await WaitUntilAsync(async () => await CountDeliveriesAsync(subscribedB, cancellationToken) == 1, cancellationToken);
        (await CountDeliveriesAsync(otherType, cancellationToken)).ShouldBe(0);
        (await CountDeliveriesAsync(disabled, cancellationToken)).ShouldBe(0);

        // Force a redelivery of the source event: null out its fast-lane outbox row so the
        // dispatcher re-fans-it-out. The unique (endpoint_id, event_id) makes the re-run a
        // no-op, so no second delivery row appears.
        var eventId = await ReadDeliveryEventIdAsync(subscribedA, cancellationToken);
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update platform.outbox set delivered_at = null, next_attempt_at = now() where event_id = @id and lane = 'fast'",
            cancellationToken,
            ("id", eventId));
        await WaitUntilAsync(
            async () => await PlatformWorkflow.CountAsync(
                fixture,
                "select count(*) from platform.outbox where event_id = @id and lane = 'fast' and delivered_at is not null and poisoned_at is null",
                cancellationToken,
                ("id", eventId)) == 1,
            cancellationToken);

        (await CountDeliveriesAsync(subscribedA, cancellationToken)).ShouldBe(1);
        (await CountDeliveriesAsync(subscribedB, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task Rls_IsolatesEndpointsAndDeliveries_BetweenTenants()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var ownerA = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var (endpointA, _) = await InsertEndpointAsync(ownerA.TenantId, DeadUrl(), NoteSubscription, disabled: false, cancellationToken);
        var (endpointB, _) = await InsertEndpointAsync(ownerB.TenantId, DeadUrl(), NoteSubscription, disabled: false, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, ownerA.Token, "Tenant A note", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        // The fan-out for tenant A creates a row for A's endpoint and never for B's.
        await WaitUntilAsync(async () => await CountDeliveriesAsync(endpointA, cancellationToken) == 1, cancellationToken);
        (await CountDeliveriesAsync(endpointB, cancellationToken)).ShouldBe(0);

        // The read path is RLS-scoped too: A's admin lists A's endpoint deliveries, but B's
        // endpoint is invisible to A and A's is invisible to B (both collapse to 404).
        var ownVisible = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/webhooks/{endpointA}/deliveries", ownerA.Token, cancellationToken);
        ownVisible.StatusCode.ShouldBe(HttpStatusCode.OK);

        var crossTenant = await TenantWorkflow.GetAsync(
            fixture, $"/api/v1/tenant/webhooks/{endpointA}/deliveries", ownerB.Token, cancellationToken);
        crossTenant.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Delivery_Succeeds_AndIsSignedWithAFreshTimestamp()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await using var receiver = new WebhookStubReceiver(statusCode: 200);
        var (endpointId, secret) = await InsertEndpointAsync(
            owner.TenantId, receiver.Url, NoteSubscription, disabled: false, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Deliver me", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        await WaitUntilAsync(() => Task.FromResult(receiver.Count >= 1), cancellationToken);
        await WaitForDeliveryStatusAsync(endpointId, WebhookDeliveryStatus.Delivered, cancellationToken);

        var received = receiver.Received[0];

        // The delivered body is the envelope { id, type, occurredAt, data } (webhooks.md
        // section 5), NOT the raw event payload: the receiver dedupes on id, filters on
        // type, and reads the event under data.
        var deliveryId = await ReadDeliveryIdAsync(endpointId, cancellationToken);
        var eventId = await ReadDeliveryEventIdAsync(endpointId, cancellationToken);
        var envelope = System.Text.Json.Nodes.JsonNode.Parse(received.Body)!.AsObject();
        envelope["type"]!.GetValue<string>().ShouldBe(NoteEvent);
        // The envelope id is the delivery row id (the receiver's dedup key).
        envelope["id"]!.GetValue<string>().ShouldBe(deliveryId.ToString());
        envelope.ContainsKey("occurredAt").ShouldBeTrue();
        // data is the source event payload verbatim (canonically equal).
        var sourcePayload = await ReadDomainEventPayloadAsync(eventId, cancellationToken);
        envelope["data"]!.ToJsonString()
            .ShouldBe(System.Text.Json.Nodes.JsonNode.Parse(sourcePayload)!.ToJsonString());

        received.Signature.ShouldNotBeNull();
        var (timestamp, signature) = ParseSignature(received.Signature!);

        // The signature verifies against the endpoint's secret over "{t}.{body}" - i.e.
        // over the envelope the receiver actually got...
        var expected = Convert.ToHexStringLower(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{received.Body}")));
        signature.ShouldBe(expected);

        // ...and its timestamp is fresh (a captured request cannot be replayed later).
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Math.Abs(now - timestamp).ShouldBeLessThan(300);
    }

    [Fact]
    public async Task RetryAndDeadLetter_WhileAHealthySibling_DeliversExactlyOnce()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await using var failing = new WebhookStubReceiver(statusCode: 500);
        await using var healthy = new WebhookStubReceiver(statusCode: 200);

        var (failEndpoint, _) = await InsertEndpointAsync(owner.TenantId, failing.Url, NoteSubscription, disabled: false, cancellationToken);
        var (healthyEndpoint, _) = await InsertEndpointAsync(owner.TenantId, healthy.Url, NoteSubscription, disabled: false, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Retry me", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        // The failing endpoint climbs to MaxAttempts (3) and dead-letters.
        await WaitForDeliveryStatusAsync(failEndpoint, WebhookDeliveryStatus.Dead, cancellationToken);
        (await ReadDeliveryAttemptsAsync(failEndpoint, cancellationToken)).ShouldBe(3);
        failing.Count.ShouldBeGreaterThanOrEqualTo(2); // retried, not one-and-done

        // The healthy sibling still delivers, exactly once (one failure never re-hits a
        // success).
        await WaitForDeliveryStatusAsync(healthyEndpoint, WebhookDeliveryStatus.Delivered, cancellationToken);
        healthy.Count.ShouldBe(1);
    }

    [Fact]
    public async Task Replay_ResendsADeadDelivery_AndItCanThenSucceed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        await using var receiver = new WebhookStubReceiver(statusCode: 500);
        var (endpointId, _) = await InsertEndpointAsync(
            owner.TenantId, receiver.Url, NoteSubscription, disabled: false, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Replay me", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        await WaitForDeliveryStatusAsync(endpointId, WebhookDeliveryStatus.Dead, cancellationToken);
        var deliveryId = await ReadDeliveryIdAsync(endpointId, cancellationToken);

        // The receiver recovers; replaying the dead delivery re-sends it and it succeeds.
        receiver.StatusCode = 200;
        var replay = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/webhooks/deliveries/{deliveryId}/replay", owner.Token, new { }, cancellationToken);
        replay.StatusCode.ShouldBe(HttpStatusCode.Accepted);

        await WaitForDeliveryStatusAsync(endpointId, WebhookDeliveryStatus.Delivered, cancellationToken);
    }

    [Fact]
    public async Task Secret_IsShownOnce_AndStoredEncrypted()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A registerable https endpoint whose host resolves public (so register passes);
        // it subscribes to note events only, so no webhook fires during this test.
        var host = $"sink-{Guid.CreateVersion7():N}.starter.test";
        fixture.WebhookDns.Map(host, "93.184.216.34");

        var register = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/webhooks",
            owner.Token,
            new { url = $"https://{host}/hook", description = "sink", eventTypes = NoteSubscription },
            cancellationToken);
        register.StatusCode.ShouldBe(HttpStatusCode.Created);

        Guid id;
        string rawSecret;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(register, cancellationToken))
        {
            id = doc.RootElement.GetProperty("id").GetGuid();
            rawSecret = doc.RootElement.GetProperty("secret").GetString()!;
        }

        rawSecret.ShouldStartWith("whsec_");

        // The list never carries the secret or its ciphertext, only the display prefix.
        var list = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/webhooks", owner.Token, cancellationToken);
        list.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(list, cancellationToken))
        {
            var item = doc.RootElement.GetProperty("items").EnumerateArray()
                .Single(entry => entry.GetProperty("id").GetGuid() == id);
            item.TryGetProperty("secret", out _).ShouldBeFalse();
            item.TryGetProperty("signingSecretEncrypted", out _).ShouldBeFalse();
            item.GetProperty("secretPrefix").GetString().ShouldBe(rawSecret[..12]);
        }

        // The stored column is DataProtection ciphertext, not the raw secret, and Unprotect
        // recovers it.
        var ciphertext = await ReadEndpointCiphertextAsync(id, cancellationToken);
        ciphertext.ShouldNotBe(rawSecret);
        var protector = fixture.Factory.Services.GetRequiredService<WebhookSecretProtector>();
        protector.Unprotect(ciphertext).ShouldBe(rawSecret);
    }

    [Fact]
    public async Task Register_RejectsNonHttps_NonAbsolute_AndLiteralInternalTargets()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Plaintext http, a non-absolute url, and a literal private target are all 422.
        (await RegisterUrlAsync(owner, "http://example.com/hook", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
        (await RegisterUrlAsync(owner, "/relative/hook", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
        (await RegisterUrlAsync(owner, "https://10.0.0.1/hook", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task Delivery_ToAResolvedInternalAddress_NeverConnects()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A host that resolves to the cloud metadata endpoint. Inserted directly (register
        // would reject the literal), so this isolates the connect-time guard: the worker
        // must never open a socket to 169.254.169.254.
        var host = $"metadata-{Guid.CreateVersion7():N}.starter.test";
        fixture.WebhookDns.Map(host, "169.254.169.254");
        var (endpointId, _) = await InsertEndpointAsync(
            owner.TenantId, $"https://{host}/hook", NoteSubscription, disabled: false, cancellationToken);

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "SSRF", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        // The delivery fails to connect, retries, and dead-letters - never delivered.
        await WaitForDeliveryStatusAsync(endpointId, WebhookDeliveryStatus.Dead, cancellationToken);
        (await ReadDeliveryScalarAsync<DateTime?>("delivered_at", endpointId, cancellationToken)).ShouldBeNull();
        (await ReadDeliveryScalarAsync<string?>("last_error", endpointId, cancellationToken)).ShouldBe("transport_error");
    }

    [Fact]
    public async Task Delivery_DnsRebinding_PublicAtRegister_PrivateAtConnect_NeverConnects()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // Public at registration...
        var host = $"rebind-{Guid.CreateVersion7():N}.starter.test";
        fixture.WebhookDns.Map(host, "93.184.216.34");

        var register = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/webhooks",
            owner.Token,
            new { url = $"https://{host}/hook", description = "rebind", eventTypes = NoteSubscription },
            cancellationToken);
        register.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid endpointId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(register, cancellationToken))
        {
            endpointId = doc.RootElement.GetProperty("id").GetGuid();
        }

        // ...private at connect: the connect-time guard resolves once and blocks, even
        // though registration passed.
        fixture.WebhookDns.Map(host, "10.0.0.5");

        (await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Rebind", cancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.Created);

        await WaitForDeliveryStatusAsync(endpointId, WebhookDeliveryStatus.Dead, cancellationToken);
        (await ReadDeliveryScalarAsync<DateTime?>("delivered_at", endpointId, cancellationToken)).ShouldBeNull();
        (await ReadDeliveryScalarAsync<string?>("last_error", endpointId, cancellationToken)).ShouldBe("transport_error");
    }

    [Fact]
    public async Task EndpointLifecycle_IsAudited_CreateUpdateRotateDelete()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var host = $"audit-{Guid.CreateVersion7():N}.starter.test";
        fixture.WebhookDns.Map(host, "93.184.216.34");

        var register = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/tenant/webhooks",
            owner.Token,
            new { url = $"https://{host}/hook", description = "audited", eventTypes = NoteSubscription },
            cancellationToken);
        register.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid id;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(register, cancellationToken))
        {
            id = doc.RootElement.GetProperty("id").GetGuid();
        }

        var update = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/webhooks/{id}", owner.Token, new { description = "updated" }, cancellationToken);
        update.StatusCode.ShouldBe(HttpStatusCode.OK);

        var rotate = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/webhooks/{id}/rotate-secret", owner.Token, new { }, cancellationToken);
        rotate.StatusCode.ShouldBe(HttpStatusCode.OK);

        var delete = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/tenant/webhooks/{id}", owner.Token, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await WaitForAuditAsync(owner.Token, $"?action=tenancy.webhook.endpoint_created&entity={id}", cancellationToken);
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.webhook.endpoint_updated&entity={id}", cancellationToken);
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.webhook.secret_rotated&entity={id}", cancellationToken);
        await WaitForAuditAsync(owner.Token, $"?action=tenancy.webhook.endpoint_deleted&entity={id}", cancellationToken);
    }

    [Fact]
    public async Task PermissionGate_RequiresWebhooksManage()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // A plain member has no webhooks:manage -> 403 starter:permission-required.
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var memberList = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/webhooks", member.Token, cancellationToken);
        memberList.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(memberList, cancellationToken))
        {
            doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:permission-required");
        }

        // An admin (webhooks:manage is in the Admin system-role set) succeeds.
        var admin = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "admin", cancellationToken);
        var adminList = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/webhooks", admin.Token, cancellationToken);
        adminList.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // --- helpers ---------------------------------------------------------

    private static string DeadUrl() => "http://127.0.0.1:1/hook";

    private async Task<(Guid Id, string Secret)> InsertEndpointAsync(
        Guid tenantId, string url, string[] eventTypes, bool disabled, CancellationToken cancellationToken)
    {
        var secret = WebhookSecrets.NewSecret();
        var protector = fixture.Factory.Services.GetRequiredService<WebhookSecretProtector>();
        var ciphertext = protector.Protect(secret);
        var id = Guid.CreateVersion7();

        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            insert into platform.webhook_endpoints
              (id, tenant_id, url, description, event_types, signing_secret_encrypted, secret_prefix, disabled_at, created_by, created_at, updated_at)
            values (@id, @tenant, @url, 'stub', @types, @cipher, @prefix, @disabled, @creator, now(), now())
            """,
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("url", url);
        command.Parameters.AddWithValue("types", eventTypes);
        command.Parameters.AddWithValue("cipher", ciphertext);
        command.Parameters.AddWithValue("prefix", WebhookSecrets.Prefix(secret));
        command.Parameters.AddWithValue("disabled", disabled ? DateTimeOffset.UtcNow : DBNull.Value);
        command.Parameters.AddWithValue("creator", Guid.CreateVersion7());
        await command.ExecuteNonQueryAsync(cancellationToken);

        return (id, secret);
    }

    private Task<HttpResponseMessage> RegisterUrlAsync(OwnerContext owner, string url, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/webhooks", owner.Token, new { url, description = "x", eventTypes = NoteSubscription }, cancellationToken);

    private Task<long> CountDeliveriesAsync(Guid endpointId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.webhook_deliveries where endpoint_id = @ep",
            cancellationToken,
            ("ep", endpointId));

    private async Task<Guid> ReadDeliveryEventIdAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select event_id from platform.webhook_deliveries where endpoint_id = @ep limit 1", connection);
        command.Parameters.AddWithValue("ep", endpointId);
        return (Guid)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<Guid> ReadDeliveryIdAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select id from platform.webhook_deliveries where endpoint_id = @ep limit 1", connection);
        command.Parameters.AddWithValue("ep", endpointId);
        return (Guid)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<int> ReadDeliveryAttemptsAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select attempts from platform.webhook_deliveries where endpoint_id = @ep limit 1", connection);
        command.Parameters.AddWithValue("ep", endpointId);
        return (int)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<T?> ReadDeliveryScalarAsync<T>(string column, Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            $"select {column} from platform.webhook_deliveries where endpoint_id = @ep limit 1", connection);
        command.Parameters.AddWithValue("ep", endpointId);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? default : (T)value;
    }

    private async Task<string> ReadDomainEventPayloadAsync(Guid eventId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select payload from platform.domain_events where id = @id", connection);
        command.Parameters.AddWithValue("id", eventId);
        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<string> ReadEndpointCiphertextAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select signing_secret_encrypted from platform.webhook_endpoints where id = @id", connection);
        command.Parameters.AddWithValue("id", endpointId);
        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private async Task<string?> ReadDeliveryStatusAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select status from platform.webhook_deliveries where endpoint_id = @ep limit 1", connection);
        command.Parameters.AddWithValue("ep", endpointId);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    private async Task WaitForDeliveryStatusAsync(Guid endpointId, string status, CancellationToken cancellationToken) =>
        await WaitUntilAsync(async () => await ReadDeliveryStatusAsync(endpointId, cancellationToken) == status, cancellationToken);

    private async Task WaitForAuditAsync(string token, string query, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var response = await TenantWorkflow.GetAsync(fixture, "/api/v1/tenant/audit" + query, token, cancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.OK);
            using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
            if (doc.RootElement.GetProperty("items").GetArrayLength() > 0)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No audit row for '{query}' appeared within the deadline.");
    }

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

    private static (long Timestamp, string Signature) ParseSignature(string header)
    {
        long timestamp = 0;
        var signature = string.Empty;
        foreach (var part in header.Split(','))
        {
            var pair = part.Split('=', 2);
            if (pair.Length != 2)
            {
                continue;
            }

            if (pair[0] == "t")
            {
                timestamp = long.Parse(pair[1], System.Globalization.CultureInfo.InvariantCulture);
            }
            else if (pair[0] == "v1")
            {
                signature = pair[1];
            }
        }

        return (timestamp, signature);
    }
}
