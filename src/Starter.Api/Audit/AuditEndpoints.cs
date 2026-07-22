using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Api.Platform;
using Starter.Api.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Http;
using Starter.Platform.Tenancy;

namespace Starter.Api.Audit;

/// <summary>
/// HTTP composition for the audit log (audit-log.md section 6): the tenant-admin
/// read over the active tenant (<c>GET /api/v1/tenant/audit</c>, gated by
/// <c>audit:read</c>, RLS-scoped to the caller's tenant) and the super-admin read
/// across tenants (<c>GET /api/v1/platform/audit</c>, behind RequirePlatformAdmin,
/// with a <c>tenant</c> filter and a <c>scope=platform</c> selector). Business
/// logic (RLS-bound and bypass reads) lives behind the Platform-registered
/// <see cref="IAuditQuery"/> / <see cref="IAuditAdminQuery"/>; this layer shapes
/// the query string and the problem envelope only. Reads are not re-audited (an
/// off-by-default extension, audit-log.md section 6).
/// </summary>
public static class AuditEndpoints
{
    private const string PlatformScope = "platform";

    public static IEndpointRouteBuilder MapTenantAuditEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an
        // unresolved tenant answers 400 tenant-required before any 403.
        var tenant = app.MapGroup("/api/v1/tenant")
            .RequireTenant()
            .RequireAuthorization();

        tenant.MapGet("/audit", QueryTenantAuditAsync).RequirePermission(Permissions.AuditRead);

        return app;
    }

    public static IEndpointRouteBuilder MapPlatformAuditEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var platform = app.MapGroup("/api/v1/platform")
            .RequireAuthorization()
            .RequirePlatformAdmin();

        platform.MapGet("/audit", QueryPlatformAuditAsync);

        return app;
    }

    private static async Task<IResult> QueryTenantAuditAsync(
        IAuditQuery audit,
        HttpContext http,
        CancellationToken cancellationToken,
        Guid? actor = null,
        string? action = null,
        Guid? entity = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int? limit = null,
        string? before = null)
    {
        var filter = new AuditQueryFilter(actor, action, entity, from, to, limit, before);
        var page = await audit.QueryAsync(filter, cancellationToken);
        if (page.IsFailure)
        {
            // A malformed cursor is a Validation failure -> 422.
            return page.Error.ToProblemResult(http);
        }

        return Results.Ok(ToResponse(page.Value));
    }

    private static async Task<IResult> QueryPlatformAuditAsync(
        IAuditAdminQuery audit,
        HttpContext http,
        CancellationToken cancellationToken,
        Guid? tenant = null,
        string? scope = null,
        Guid? actor = null,
        string? action = null,
        Guid? entity = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        int? limit = null,
        string? before = null)
    {
        var filter = new AuditQueryFilter(actor, action, entity, from, to, limit, before);

        if (string.Equals(scope, PlatformScope, StringComparison.OrdinalIgnoreCase))
        {
            var platformPage = await audit.QueryPlatformAsync(filter, cancellationToken);
            if (platformPage.IsFailure)
            {
                return platformPage.Error.ToProblemResult(http);
            }

            var platformItems = platformPage.Value.Items
                .Select(entry => new PlatformAuditEntryResponse(
                    entry.Id,
                    entry.OccurredAt,
                    entry.RecordedAt,
                    entry.Action,
                    entry.ActorUserId,
                    entry.SubjectUserId,
                    entry.Summary,
                    ParseData(entry.Data)))
                .ToList();
            return Results.Ok(new AuditPageResponse<PlatformAuditEntryResponse>(
                platformItems, platformPage.Value.NextCursor));
        }

        var page = await audit.QueryTenantAsync(tenant, filter, cancellationToken);
        if (page.IsFailure)
        {
            return page.Error.ToProblemResult(http);
        }

        return Results.Ok(ToResponse(page.Value));
    }

    private static AuditPageResponse<AuditEntryResponse> ToResponse(AuditPage<AuditEntry> page)
    {
        var items = page.Items
            .Select(entry => new AuditEntryResponse(
                entry.Id,
                entry.TenantId,
                entry.OccurredAt,
                entry.RecordedAt,
                entry.Action,
                entry.ActorUserId,
                entry.EntityId,
                entry.Summary,
                ParseData(entry.Data)))
            .ToList();
        return new AuditPageResponse<AuditEntryResponse>(items, page.NextCursor);
    }

    // The stored data is the event payload verbatim (jsonb). Emit it as raw JSON,
    // not an escaped string: parse to a detached JsonNode so it serializes as an
    // object. A payload that is somehow not JSON degrades to null rather than 500.
    private static JsonNode? ParseData(string data)
    {
        try
        {
            return JsonNode.Parse(data);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }
}

/// <summary>A page of audit entries: <c>{ "items": [...], "nextCursor": "..." | null }</c>.</summary>
public sealed record AuditPageResponse<T>(IReadOnlyList<T> Items, string? NextCursor);

/// <summary>GET /api/v1/tenant/audit (and the tenant projection view of the platform read) item.</summary>
public sealed record AuditEntryResponse(
    Guid Id,
    Guid TenantId,
    DateTimeOffset OccurredAt,
    DateTimeOffset RecordedAt,
    string Action,
    Guid? ActorUserId,
    Guid? EntityId,
    string Summary,
    JsonNode? Data);

/// <summary>GET /api/v1/platform/audit?scope=platform item.</summary>
public sealed record PlatformAuditEntryResponse(
    Guid Id,
    DateTimeOffset OccurredAt,
    DateTimeOffset RecordedAt,
    string Action,
    Guid? ActorUserId,
    Guid? SubjectUserId,
    string Summary,
    JsonNode? Data);
