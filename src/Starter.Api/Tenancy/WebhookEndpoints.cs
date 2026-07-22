using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Platform.Auth;
using Starter.Platform.Http;
using Starter.Platform.Paging;
using Starter.Platform.Tenancy;
using Starter.Platform.Webhooks;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the tenant webhook control plane (webhooks.md section 7), all
/// over the ACTIVE tenant (/api/v1/tenant/webhooks) and gated by the group-level
/// RequireTenant + RequireAuthorization and per-route
/// RequirePermission(webhooks:manage). Business rules (RLS-bound register / list / update
/// / rotate / delete / delivery-list / replay) live behind the Platform-registered
/// <see cref="IWebhookAdmin"/>; this layer shapes requests, transports, and the problem
/// envelope only, and never touches the internal context or the bypass path. The raw
/// signing secret is returned ONCE at register and rotate and never listed.
/// </summary>
public static class WebhookEndpoints
{
    public static IEndpointRouteBuilder MapWebhookEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-level gates run before the per-route permission gate, so an unresolved
        // tenant answers 400 tenant-required before any 403.
        var webhooks = app.MapGroup("/api/v1/tenant/webhooks")
            .RequireTenant()
            .RequireAuthorization();

        webhooks.MapPost("/", RegisterAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapGet("/", ListAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapPatch("/{id:guid}", UpdateAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapPost("/{id:guid}/rotate-secret", RotateSecretAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapDelete("/{id:guid}", DeleteAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapGet("/{id:guid}/deliveries", ListDeliveriesAsync).RequirePermission(Permissions.WebhooksManage);
        webhooks.MapPost("/deliveries/{id:guid}/replay", ReplayAsync).RequirePermission(Permissions.WebhooksManage);

        return app;
    }

    private static async Task<IResult> RegisterAsync(
        RegisterWebhookRequest request,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await webhooks.RegisterAsync(
            callerId.Value, request.Url ?? string.Empty, request.Description, request.EventTypes, cancellationToken);
        return result.Match(
            registered => (IResult)TypedResults.Created(
                (string?)null,
                new WebhookRegisteredResponse(
                    registered.Id, registered.Secret, registered.SecretPrefix, registered.Url, registered.CreatedAt)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> ListAsync(
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken,
        int? limit = null,
        string? cursor = null)
    {
        var result = await webhooks.ListEndpointsAsync(PageLimit.Clamp(limit), cursor, cancellationToken);
        return result.Match(
            page => Results.Ok(new CursorPage<WebhookEndpointResponse>(
                page.Items.Select(ToResponse).ToList(), page.NextCursor)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateWebhookRequest request,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await webhooks.UpdateAsync(
            callerId.Value, id, request.Url, request.Description, request.EventTypes, request.Disabled, cancellationToken);
        return result.Match(
            updated => Results.Ok(ToResponse(updated)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> RotateSecretAsync(
        Guid id,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await webhooks.RotateSecretAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            rotated => Results.Ok(new RotateWebhookSecretResponse(rotated.Secret, rotated.SecretPrefix)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var callerId = http.User.GetUserId();
        if (callerId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var result = await webhooks.DeleteAsync(callerId.Value, id, cancellationToken);
        return result.Match(
            () => Results.NoContent(),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> ListDeliveriesAsync(
        Guid id,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken,
        int? limit = null,
        string? cursor = null)
    {
        var result = await webhooks.ListDeliveriesAsync(id, PageLimit.Clamp(limit), cursor, cancellationToken);
        return result.Match(
            page => Results.Ok(new CursorPage<WebhookDeliveryResponse>(
                page.Items.Select(ToResponse).ToList(), page.NextCursor)),
            error => error.ToProblemResult(http));
    }

    private static async Task<IResult> ReplayAsync(
        Guid id,
        IWebhookAdmin webhooks,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await webhooks.ReplayDeliveryAsync(id, cancellationToken);
        return result.Match(
            () => Results.Accepted(),
            error => error.ToProblemResult(http));
    }

    private static WebhookEndpointResponse ToResponse(WebhookEndpointView view) =>
        new(view.Id, view.Url, view.Description, view.EventTypes, view.Disabled, view.SecretPrefix, view.CreatedAt, view.UpdatedAt);

    private static WebhookDeliveryResponse ToResponse(WebhookDeliveryView view) =>
        new(
            view.Id,
            view.EndpointId,
            view.EventId,
            view.EventType,
            view.Status,
            view.Attempts,
            view.NextAttemptAt,
            view.DeliveredAt,
            view.DeadLetteredAt,
            view.LastResponseStatus,
            view.LastError,
            view.CreatedAt);
}

/// <summary>POST /api/v1/tenant/webhooks body: the receiver url (https), an admin label, and optional subscribed event types (empty = all).</summary>
public sealed record RegisterWebhookRequest(string? Url, string? Description, IReadOnlyList<string>? EventTypes);

/// <summary>POST /api/v1/tenant/webhooks success: the new endpoint id, the raw signing secret (returned ONCE), its display prefix, the url, and when it was created.</summary>
public sealed record WebhookRegisteredResponse(
    Guid Id, string Secret, string SecretPrefix, string Url, DateTimeOffset CreatedAt);

/// <summary>PATCH /api/v1/tenant/webhooks/{id} body: any subset of url / description / event types / disabled to change.</summary>
public sealed record UpdateWebhookRequest(
    string? Url, string? Description, IReadOnlyList<string>? EventTypes, bool? Disabled);

/// <summary>A webhook endpoint as listed or updated: never the secret or its ciphertext, only the display prefix.</summary>
public sealed record WebhookEndpointResponse(
    Guid Id,
    string Url,
    string Description,
    IReadOnlyList<string> EventTypes,
    bool Disabled,
    string SecretPrefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>POST /api/v1/tenant/webhooks/{id}/rotate-secret success: the new raw secret (once) and its prefix.</summary>
public sealed record RotateWebhookSecretResponse(string Secret, string SecretPrefix);

/// <summary>A webhook delivery-log row.</summary>
public sealed record WebhookDeliveryResponse(
    Guid Id,
    Guid EndpointId,
    Guid EventId,
    string EventType,
    string Status,
    int Attempts,
    DateTimeOffset NextAttemptAt,
    DateTimeOffset? DeliveredAt,
    DateTimeOffset? DeadLetteredAt,
    int? LastResponseStatus,
    string? LastError,
    DateTimeOffset CreatedAt);
