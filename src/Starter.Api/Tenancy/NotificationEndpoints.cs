using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Notifications;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the in-app inbox (in-app-notifications.md section 4): the
/// caller's own notifications over the active tenant, all under
/// <c>RequireTenant</c> + <c>RequireAuthorization</c> with NO permission atom -
/// reading and marking your own inbox is your own data, so the endpoints gate on
/// authentication only and filter <c>recipient_user_id = caller</c>. A member can
/// never see another member's notifications (RLS scopes the tenant, the recipient
/// filter scopes the user), and a foreign id reads as 404 (invisible), never 403.
/// Business logic (the RLS-bound reads and updates) lives behind the
/// Platform-registered <see cref="INotificationService"/>; this layer shapes the
/// query string and the problem envelope only.
/// </summary>
public static class NotificationEndpoints
{
    public static IEndpointRouteBuilder MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the handler, so an unresolved tenant
        // answers 400 tenant-required before any per-user work.
        var tenant = app.MapGroup("/api/v1/tenant")
            .RequireTenant()
            .RequireAuthorization();

        tenant.MapGet("/notifications", ListAsync);
        tenant.MapGet("/notifications/unread-count", UnreadCountAsync);
        tenant.MapPost("/notifications/{id:guid}/read", MarkReadAsync);
        tenant.MapPost("/notifications/read-all", MarkAllReadAsync);

        return app;
    }

    private static async Task<IResult> ListAsync(
        INotificationService notifications,
        HttpContext http,
        CancellationToken cancellationToken,
        bool? unread = null,
        int? limit = null,
        string? cursor = null)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var page = await notifications.ListAsync(
            callerId.Value, unread ?? false, limit, cursor, cancellationToken);
        if (page.IsFailure)
        {
            // A malformed cursor is a Validation failure -> 422.
            return page.Error.ToProblemResult(http);
        }

        var items = page.Value.Items
            .Select(item => new NotificationResponse(
                item.Id, item.Type, ParseData(item.Data), item.CreatedAt, item.ReadAt))
            .ToList();
        return Results.Ok(new NotificationsPageResponse(items, page.Value.NextCursor));
    }

    private static async Task<IResult> UnreadCountAsync(
        INotificationService notifications,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var count = await notifications.UnreadCountAsync(callerId.Value, cancellationToken);
        return Results.Ok(new UnreadCountResponse(count));
    }

    private static async Task<IResult> MarkReadAsync(
        Guid id,
        INotificationService notifications,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await notifications.MarkReadAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> MarkAllReadAsync(
        INotificationService notifications,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var marked = await notifications.MarkAllReadAsync(callerId.Value, cancellationToken);
        return Results.Ok(new MarkAllReadResponse(marked));
    }

    // The stored data is the render jsonb verbatim. Emit it as raw JSON, not an
    // escaped string: parse to a detached JsonNode so it serializes as an object.
    // Data that is somehow not JSON degrades to null rather than 500.
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

/// <summary>A page of notifications: <c>{ "items": [...], "nextCursor": "..." | null }</c>.</summary>
public sealed record NotificationsPageResponse(IReadOnlyList<NotificationResponse> Items, string? NextCursor);

/// <summary>GET /api/v1/tenant/notifications item.</summary>
public sealed record NotificationResponse(
    Guid Id,
    string Type,
    JsonNode? Data,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ReadAt);

/// <summary>GET /api/v1/tenant/notifications/unread-count response: <c>{ "count": n }</c>.</summary>
public sealed record UnreadCountResponse(int Count);

/// <summary>POST /api/v1/tenant/notifications/read-all response: <c>{ "marked": n }</c>.</summary>
public sealed record MarkAllReadResponse(int Marked);
