using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Tenancy;
using Starter.Sample;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The crown-jewel suite: one tenant can never read or write another tenant's
/// data. It proves the boundary at every layer - the HTTP surface (404, never a
/// cross-tenant row in a list), raw SQL on the request role (RLS holds below
/// EF), the connection pool (SET LOCAL is transaction-scoped, no stale tenant),
/// the bypass escape hatch (only it crosses tenants), and the async consumer
/// path (a tenant-bound consumer sees only its tenant).
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class TenantIsolationTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Isolation-Passphrase-5f1c";

    [Fact]
    public async Task TenantScopedEndpoint_WithNoResolvableTenant_Is400TenantRequired()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"iso-notenant-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);

        // Authenticated, but no tenant supplied by any source (no tid claim,
        // no X-Tenant, no path or subdomain): the tenant-scoped endpoint answers
        // 400 with the stable starter:tenant-required type.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/sample/notes");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await fixture.Client.SendAsync(request, cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:tenant-required");
    }

    [Fact]
    public async Task CrossTenant_ReadDeleteList_NeverSeeAnotherTenantsNote()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var token = await fixture.RegisterVerifyLoginAsync(
            $"iso-http-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();

        // Create a note under tenant A.
        var create = await SendAsync(HttpMethod.Post, "/api/v1/sample/notes", token, tenantA,
            new { title = "A secret", body = "belongs to tenant A" }, cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid noteId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            noteId = doc.RootElement.GetProperty("id").GetGuid();
        }

        // The SAME caller, acting under tenant B, cannot read it: 404 (not 403,
        // to avoid confirming the row exists).
        var readUnderB = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{noteId}", token, tenantB, body: null, cancellationToken);
        readUnderB.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // Nor delete it under tenant B: 404.
        var deleteUnderB = await SendAsync(
            HttpMethod.Delete, $"/api/v1/sample/notes/{noteId}", token, tenantB, body: null, cancellationToken);
        deleteUnderB.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // Under tenant A it is readable (the row really does exist), so the 404s
        // above are the tenant boundary, not a missing row.
        var readUnderA = await SendAsync(
            HttpMethod.Get, $"/api/v1/sample/notes/{noteId}", token, tenantA, body: null, cancellationToken);
        readUnderA.StatusCode.ShouldBe(HttpStatusCode.OK);

        // B's list never shows A's note; A's list does.
        (await ListNoteIdsAsync(token, tenantB, cancellationToken)).ShouldNotContain(noteId);
        (await ListNoteIdsAsync(token, tenantA, cancellationToken)).ShouldContain(noteId);
    }

    [Fact]
    public async Task Rls_NotJustEf_RawQueryOnRequestRole_WithWrongOrAbsentGuc_ReturnsZeroRows()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();
        await SeedNoteAsync(tenantA, Guid.CreateVersion7(), "A row", cancellationToken);

        // Raw SQL on the request role bypasses the EF query filter entirely, so
        // a zero here is RLS, not EF. The count is over tenant A's row only
        // (tenant A is a fresh id), so: wrong tenant GUC -> zero.
        (await CountNotesAsync(fixture.RequestDataSource, guc: tenantB, cancellationToken))
            .ShouldBe(0);
        // Absent GUC -> zero (current_setting returns NULL, the policy matches
        // nothing: fail-closed).
        (await CountNotesAsync(fixture.RequestDataSource, guc: null, cancellationToken))
            .ShouldBe(0);
        // Correct tenant -> the row is visible, so RLS is scoping, not just
        // hiding everything (tenant A is fresh, so its one row is the only one
        // visible under its GUC).
        (await CountNotesAsync(fixture.RequestDataSource, guc: tenantA, cancellationToken))
            .ShouldBe(1);
    }

    [Fact]
    public async Task Rls_OnTheRealInterceptorPath_WithEfFilterIgnored_StillHidesOtherTenants()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();
        await SeedNoteAsync(tenantA, Guid.CreateVersion7(), "A on real path", cancellationToken);
        await SeedNoteAsync(tenantB, Guid.CreateVersion7(), "B on real path", cancellationToken);

        // The real path: a scope with the tenant set exactly as the middleware
        // (or dispatcher) sets it, and the module's own DbContext resolved from
        // that same scope, so its transaction fires the interceptor and the GUC
        // is set by the interceptor - not hand-set SQL.
        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().Resolve(tenantA, slug: null);
        var db = scope.ServiceProvider.GetRequiredService<SampleDbContext>();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // IgnoreQueryFilters strips the EF global filter, so a negative here can
        // only be RLS + the interceptor, never the EF filter. Tenant B stays
        // invisible even asking for it directly, and only tenant A's row is
        // returned when the filter is off - proving the DB layer is the
        // boundary (a consumer that forgets to filter still cannot cross).
        var crossTenant = await db.Notes.IgnoreQueryFilters()
            .Where(note => note.TenantId == tenantB)
            .ToListAsync(cancellationToken);
        crossTenant.ShouldBeEmpty();

        var visibleWithoutFilter = await db.Notes.IgnoreQueryFilters().ToListAsync(cancellationToken);
        visibleWithoutFilter.ShouldNotBeEmpty();
        visibleWithoutFilter.ShouldAllBe(note => note.TenantId == tenantA);

        await transaction.CommitAsync(cancellationToken);
    }

    [Fact]
    public async Task EmptyStringGuc_OnAReusedConnection_FailsClosed_NeverErrors()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = Guid.CreateVersion7();
        await SeedNoteAsync(tenantA, Guid.CreateVersion7(), "A pinned", cancellationToken);

        // ONE pinned request-role connection, reused across two transactions -
        // deterministic, not relying on drawing a reused pooled connection.
        await using var connection = await fixture.RequestDataSource.OpenConnectionAsync(cancellationToken);

        // Tx 1 sets the tenant GUC (SET LOCAL), which establishes the
        // app.current_tenant placeholder in the session, then ends: the local
        // value reverts to the EMPTY STRING, not NULL.
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            await SetTenantAsync(connection, transaction, tenantA, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        // Tx 2 on the SAME connection sets nothing. current_setting now returns
        // '' (the reset placeholder), so the policy's nullif(...,'')::uuid is
        // NULL and matches zero rows (fail-closed) - it must NOT raise 22P02 by
        // casting ''::uuid, which is exactly what the nullif form prevents.
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            await using var command = new NpgsqlCommand(
                "select count(*) from sample.notes", connection, transaction);
            var count = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
            count.ShouldBe(0);
            await transaction.CommitAsync(cancellationToken);
        }
    }

    [Fact]
    public async Task PoolInterleave_ManyTenants_NoConnectionEverCarriesAStaleTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // One note per tenant, all seeded up front.
        const int tenantCount = 16;
        var tenants = new List<(Guid Tenant, Guid NoteId)>();
        for (var i = 0; i < tenantCount; i++)
        {
            var tenant = Guid.CreateVersion7();
            var noteId = await SeedNoteAsync(tenant, Guid.CreateVersion7(), $"Pool {i}", cancellationToken);
            tenants.Add((tenant, noteId));
        }

        // Hammer the pool: many interleaved transactions, each setting its own
        // tenant, reading, and asserting it only ever saw its own row. Bounded
        // parallelism keeps well under the container's connection cap while
        // forcing a small set of pooled connections to cycle through many
        // different tenants - exactly the reuse that would surface a stale
        // SET LOCAL. If a pooled connection carried a prior transaction's
        // tenant, some task would see the wrong row (or none). SET LOCAL is
        // transaction-scoped, so none does.
        const int iterationsPerTenant = 24;
        var work = tenants
            .SelectMany(entry => Enumerable.Repeat(entry, iterationsPerTenant))
            .ToList();

        await Parallel.ForEachAsync(
            work,
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = cancellationToken },
            async (entry, token) =>
            {
                var visible = await VisibleNoteIdsAsync(fixture.RequestDataSource, guc: entry.Tenant, token);
                visible.ShouldBe([entry.NoteId]);
            });
    }

    [Fact]
    public async Task BypassContainment_RequestRoleCannotCross_BypassRoleCan()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();
        await SeedNoteAsync(tenantA, Guid.CreateVersion7(), "A", cancellationToken);
        await SeedNoteAsync(tenantB, Guid.CreateVersion7(), "B", cancellationToken);

        // The request role, bound to tenant A, cannot reach tenant B - not even
        // by trying to set a made-up bypass GUC (there is no in-band switch).
        await using (var connection = await fixture.RequestDataSource.OpenConnectionAsync(cancellationToken))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            await SetTenantAsync(connection, transaction, tenantA, cancellationToken);
            // A normal session can set any namespaced GUC, but nothing keys off
            // this one, so it grants no escalation.
            await ExecuteAsync(connection, transaction, "set local app.bypass_rls = 'on'", cancellationToken);

            (await CountWhereTenantAsync(connection, transaction, tenantB, cancellationToken)).ShouldBe(0);
            (await CountWhereTenantAsync(connection, transaction, tenantA, cancellationToken)).ShouldBe(1);
        }

        // The bypass data source (BYPASSRLS role) is the only thing that crosses
        // tenants: it sees both.
        await using (var connection = await fixture.BypassDataSource.OpenConnectionAsync(cancellationToken))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            (await CountWhereTenantAsync(connection, transaction, tenantA, cancellationToken)).ShouldBe(1);
            (await CountWhereTenantAsync(connection, transaction, tenantB, cancellationToken)).ShouldBe(1);
        }
    }

    [Fact]
    public async Task ConsumerIsolation_TenantScopedConsumer_SeesOnlyItsOwnTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();

        // Tenant B is busy: five notes. If the consumer's reads leaked across
        // the boundary, the visible-count it records for tenant A's note would
        // include these.
        for (var i = 0; i < 5; i++)
        {
            await SeedNoteAsync(tenantB, Guid.CreateVersion7(), $"B note {i}", cancellationToken);
        }

        // Create one note under tenant A over HTTP: this rides the outbox to the
        // tenant-scoped NoteIndexConsumer, which the dispatcher runs bound to
        // tenant A.
        var token = await fixture.RegisterVerifyLoginAsync(
            $"iso-consumer-{Guid.NewGuid():N}@starter.example", Password, cancellationToken);
        var create = await SendAsync(HttpMethod.Post, "/api/v1/sample/notes", token, tenantA,
            new { title = "indexed", body = "tenant A only" }, cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        Guid noteId;
        using (var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken))
        {
            noteId = doc.RootElement.GetProperty("id").GetGuid();
        }

        // The consumer runs asynchronously; wait for the projection row.
        var (tenantId, visibleNoteCount) = await WaitForIndexAsync(noteId, cancellationToken);

        // It ran under tenant A, and its broad "how many notes can I see" count
        // saw ONLY tenant A's single note - never tenant B's five.
        tenantId.ShouldBe(tenantA);
        visibleNoteCount.ShouldBe(1);
    }

    // --- HTTP helpers -----------------------------------------------------

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string uri, string token, Guid tenant, object? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("X-Tenant", tenant.ToString());
        if (method == HttpMethod.Post)
        {
            request.Headers.Add("Idempotency-Key", Guid.CreateVersion7().ToString());
        }

        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await fixture.Client.SendAsync(request, cancellationToken);
    }

    private async Task<List<Guid>> ListNoteIdsAsync(string token, Guid tenant, CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            HttpMethod.Get, "/api/v1/sample/notes", token, tenant, body: null, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid())
            .ToList();
    }

    // --- SQL helpers ------------------------------------------------------

    private async Task<Guid> SeedNoteAsync(
        Guid tenant, Guid owner, string title, CancellationToken cancellationToken)
    {
        // Seed on the admin (superuser) connection, which bypasses RLS, so a
        // test can plant rows for any tenant directly.
        var id = Guid.CreateVersion7();
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into sample.notes (id, tenant_id, owner_user_id, title, body, created_at, updated_at) "
            + "values (@id, @tenant, @owner, @title, 'body', now(), now())",
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("tenant", tenant);
        command.Parameters.AddWithValue("owner", owner);
        command.Parameters.AddWithValue("title", title);
        await command.ExecuteNonQueryAsync(cancellationToken);
        return id;
    }

    private static async Task<long> CountNotesAsync(
        NpgsqlDataSource dataSource, Guid? guc, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        if (guc is Guid tenant)
        {
            await SetTenantAsync(connection, transaction, tenant, cancellationToken);
        }

        await using var command = new NpgsqlCommand(
            "select count(*) from sample.notes", connection, transaction);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task<List<Guid>> VisibleNoteIdsAsync(
        NpgsqlDataSource dataSource, Guid guc, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, guc, cancellationToken);

        await using var command = new NpgsqlCommand(
            "select id from sample.notes", connection, transaction);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var ids = new List<Guid>();
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }

    private static async Task<long> CountWhereTenantAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid tenant, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select count(*) from sample.notes where tenant_id = @tenant", connection, transaction);
        command.Parameters.AddWithValue("tenant", tenant);
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task SetTenantAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid tenant, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select set_config('app.current_tenant', @tenant, true)", connection, transaction);
        command.Parameters.AddWithValue("tenant", tenant.ToString());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<(Guid TenantId, int VisibleNoteCount)> WaitForIndexAsync(
        Guid noteId, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await using (var connection = await fixture.OpenConnectionAsync(cancellationToken))
            await using (var command = new NpgsqlCommand(
                "select tenant_id, visible_note_count from sample.note_index where note_id = @id", connection))
            {
                command.Parameters.AddWithValue("id", noteId);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    return (reader.GetGuid(0), reader.GetInt32(1));
                }
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No sample.note_index row for {noteId} appeared within the deadline.");
    }
}
