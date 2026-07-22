using System.Net.Http.Headers;
using Npgsql;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// Shared workflow helpers for the platform super-admin and impersonation suites
/// (multi-tenancy.md sections 7 and 9), driving through the real endpoints. The
/// first platform admin is established out of band (the design forbids a
/// self-grant path), so these seed a platform.platform_admins row directly on the
/// admin (superuser) connection - the same seed-on-the-admin-connection pattern
/// the invitation seat-race test uses.
/// </summary>
internal static class PlatformWorkflow
{
    /// <summary>
    /// Registers, verifies, and logs in a fresh user, then seeds them as a
    /// platform super-admin out of band. Returns the caller's (tenant-less)
    /// access token and user id.
    /// </summary>
    public static async Task<(string Token, Guid UserId)> SignupPlatformAdminAsync(
        StarterAppFixture fixture, CancellationToken cancellationToken)
    {
        var email = TenantWorkflow.FreshEmail("padmin");
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);
        await SeedPlatformAdminAsync(fixture, userId, cancellationToken);
        return (token, userId);
    }

    /// <summary>Seeds a platform-admin row on the admin connection (bypasses RLS), idempotently.</summary>
    public static async Task SeedPlatformAdminAsync(
        StarterAppFixture fixture, Guid userId, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "insert into platform.platform_admins (user_id, granted_by, granted_at) "
            + "values (@id, null, now()) on conflict (user_id) do nothing",
            connection);
        command.Parameters.AddWithValue("id", userId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// Clears the whole platform-admin roster on the admin connection. The
    /// integration collection runs sequentially, so a test may reset this global
    /// table to make the last-admin lockout guard deterministic; later tests seed
    /// their own admins afresh.
    /// </summary>
    public static async Task ClearPlatformAdminsAsync(
        StarterAppFixture fixture, CancellationToken cancellationToken)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("delete from platform.platform_admins", connection);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// Starts an impersonation session through the real endpoint and returns the
    /// short impersonation token plus the grant id.
    /// </summary>
    public static async Task<(string Token, Guid GrantId)> StartImpersonationAsync(
        StarterAppFixture fixture,
        string adminToken,
        Guid tenantId,
        Guid? targetUserId,
        string reason,
        CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/platform/impersonation",
            adminToken,
            new { tenantId, userId = targetUserId, reason },
            cancellationToken);
        response.EnsureSuccessStatusCode();
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        var token = doc.RootElement.GetProperty("accessToken").GetString()!;
        var grantId = doc.RootElement.GetProperty("grantId").GetGuid();
        return (token, grantId);
    }

    /// <summary>An in-place SQL count on the admin connection (bypasses RLS).</summary>
    public static async Task<long> CountAsync(
        StarterAppFixture fixture,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    /// <summary>An in-place SQL statement on the admin connection (bypasses RLS).</summary>
    public static async Task ExecuteAsync(
        StarterAppFixture fixture,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Builds a bearer GET against the fixture client (for reuse where the tenant helpers do not fit).</summary>
    public static Task<HttpResponseMessage> GetAsync(
        StarterAppFixture fixture, string uri, string bearer, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return fixture.Client.SendAsync(request, cancellationToken);
    }
}
