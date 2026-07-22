using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Paging;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The tenant webhook control plane (webhooks.md section 7), all operating on the ACTIVE
/// tenant on the REQUEST path under row-level security - never the bypass path (that is
/// the worker's, for cross-tenant drain). Every write opens a transaction so the tenant
/// interceptor sets the current-tenant GUC (RLS then binds every read and write to the
/// active tenant), stamps its domain event through the <see cref="OutboxWriter"/>, and
/// commits once. The endpoint's RequirePermission(webhooks:manage) gate runs before this.
/// </summary>
internal sealed class WebhookAdminService(
    PlatformDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    WebhookSecretProtector protector,
    IWebhookDnsResolver resolver,
    IOptions<WebhookOptions> options,
    Clock clock) : IWebhookAdmin
{
    private const int MaxDescriptionLength = 256;
    private const int MaxEventTypes = 64;

    private readonly WebhookOptions _options = options.Value;

    public async Task<Result<RegisteredWebhook>> RegisterAsync(
        Guid callerUserId,
        string url,
        string? description,
        IReadOnlyList<string>? eventTypes,
        CancellationToken cancellationToken)
    {
        var validatedUrl = await ValidateUrlAsync(url, cancellationToken);
        if (validatedUrl.IsFailure)
        {
            return Result.Failure<RegisteredWebhook>(validatedUrl.Error);
        }

        var normalizedTypes = NormalizeEventTypes(eventTypes);
        if (normalizedTypes.IsFailure)
        {
            return Result.Failure<RegisteredWebhook>(normalizedTypes.Error);
        }

        var now = clock.UtcNow;
        var rawSecret = WebhookSecrets.NewSecret();
        var endpointId = Ids.NewId(now);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The per-tenant endpoint cap bounds a single event's fan-out (webhooks.md section
        // 7a). RLS scopes the count to the active tenant.
        var existing = await db.WebhookEndpoints.CountAsync(cancellationToken);
        if (existing >= _options.MaxEndpointsPerTenant)
        {
            return Result.Failure<RegisteredWebhook>(new Error(
                ErrorKind.Validation,
                "webhooks.endpoint_limit_reached",
                $"A tenant may register at most {_options.MaxEndpointsPerTenant} webhook endpoints."));
        }

        db.WebhookEndpoints.Add(new WebhookEndpointRow
        {
            Id = endpointId,
            TenantId = tenant.TenantId,
            Url = validatedUrl.Value,
            Description = NormalizeDescription(description),
            EventTypes = normalizedTypes.Value,
            SigningSecretEncrypted = protector.Protect(rawSecret),
            SecretPrefix = WebhookSecrets.Prefix(rawSecret),
            CreatedBy = callerUserId,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(db, WebhookEvents.EndpointCreated(endpointId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new RegisteredWebhook(endpointId, rawSecret, WebhookSecrets.Prefix(rawSecret), validatedUrl.Value, now);
    }

    public async Task<Result<CursorPage<WebhookEndpointView>>> ListEndpointsAsync(
        int limit, string? cursor, CancellationToken cancellationToken)
    {
        limit = PageLimit.Clamp(limit);
        if (!TryDecodeCursor(cursor, out var after))
        {
            return Result.Failure<CursorPage<WebhookEndpointView>>(CursorMalformed);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var query = db.WebhookEndpoints.AsNoTracking();
        if (after is { } key)
        {
            query = query.Where(endpoint =>
                endpoint.CreatedAt < key.CreatedAt
                || (endpoint.CreatedAt == key.CreatedAt && endpoint.Id.CompareTo(key.Id) < 0));
        }

        var rows = await query
            .OrderByDescending(endpoint => endpoint.CreatedAt)
            .ThenByDescending(endpoint => endpoint.Id)
            .Take(limit + 1)
            .Select(endpoint => new
            {
                endpoint.Id,
                endpoint.Url,
                endpoint.Description,
                endpoint.EventTypes,
                endpoint.DisabledAt,
                endpoint.SecretPrefix,
                endpoint.CreatedAt,
                endpoint.UpdatedAt,
            })
            .ToListAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = new KeysetCursor(lastKept.CreatedAt, lastKept.Id).Encode();
            rows.RemoveAt(rows.Count - 1);
        }

        var items = rows
            .Select(row => new WebhookEndpointView(
                row.Id,
                row.Url,
                row.Description,
                row.EventTypes,
                row.DisabledAt is not null,
                row.SecretPrefix,
                row.CreatedAt,
                row.UpdatedAt))
            .ToList();

        return new CursorPage<WebhookEndpointView>(items, nextCursor);
    }

    public async Task<Result<WebhookEndpointView>> UpdateAsync(
        Guid callerUserId,
        Guid endpointId,
        string? url,
        string? description,
        IReadOnlyList<string>? eventTypes,
        bool? disabled,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var endpoint = await db.WebhookEndpoints.SingleOrDefaultAsync(
            candidate => candidate.Id == endpointId, cancellationToken);
        if (endpoint is null)
        {
            return Result.Failure<WebhookEndpointView>(EndpointNotFound);
        }

        if (url is not null)
        {
            var validatedUrl = await ValidateUrlAsync(url, cancellationToken);
            if (validatedUrl.IsFailure)
            {
                return Result.Failure<WebhookEndpointView>(validatedUrl.Error);
            }

            endpoint.Url = validatedUrl.Value;
        }

        if (description is not null)
        {
            endpoint.Description = NormalizeDescription(description);
        }

        if (eventTypes is not null)
        {
            var normalizedTypes = NormalizeEventTypes(eventTypes);
            if (normalizedTypes.IsFailure)
            {
                return Result.Failure<WebhookEndpointView>(normalizedTypes.Error);
            }

            endpoint.EventTypes = normalizedTypes.Value;
        }

        if (disabled is { } shouldDisable)
        {
            endpoint.DisabledAt = shouldDisable ? endpoint.DisabledAt ?? now : null;
        }

        endpoint.UpdatedAt = now;
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(db, WebhookEvents.EndpointUpdated(endpointId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new WebhookEndpointView(
            endpoint.Id,
            endpoint.Url,
            endpoint.Description,
            endpoint.EventTypes,
            endpoint.DisabledAt is not null,
            endpoint.SecretPrefix,
            endpoint.CreatedAt,
            endpoint.UpdatedAt);
    }

    public async Task<Result<RotatedWebhookSecret>> RotateSecretAsync(
        Guid callerUserId, Guid endpointId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var rawSecret = WebhookSecrets.NewSecret();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var endpoint = await db.WebhookEndpoints.SingleOrDefaultAsync(
            candidate => candidate.Id == endpointId, cancellationToken);
        if (endpoint is null)
        {
            return Result.Failure<RotatedWebhookSecret>(EndpointNotFound);
        }

        // One active ciphertext: replacing it stops the old secret signing immediately.
        endpoint.SigningSecretEncrypted = protector.Protect(rawSecret);
        endpoint.SecretPrefix = WebhookSecrets.Prefix(rawSecret);
        endpoint.UpdatedAt = now;
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(db, WebhookEvents.SecretRotated(endpointId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new RotatedWebhookSecret(rawSecret, WebhookSecrets.Prefix(rawSecret));
    }

    public async Task<Result> DeleteAsync(Guid callerUserId, Guid endpointId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var endpoint = await db.WebhookEndpoints.SingleOrDefaultAsync(
            candidate => candidate.Id == endpointId, cancellationToken);
        if (endpoint is null)
        {
            return Result.Failure(EndpointNotFound);
        }

        // No DB-level foreign keys in this codebase, so the delete is an explicit
        // transactional statement removing the endpoint and its still-pending deliveries
        // together (webhooks.md section 7); the worker's send-time re-check covers a
        // delivery already claimed when the delete lands. Delivered/dead rows are kept as
        // the delivery-log record. RLS scopes both deletes to the active tenant.
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"delete from platform.webhook_deliveries where endpoint_id = {endpointId} and status = 'pending'",
            cancellationToken);
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"delete from platform.webhook_endpoints where id = {endpointId}",
            cancellationToken);

        await outbox.EnqueueAsync(db, WebhookEvents.EndpointDeleted(endpointId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result<CursorPage<WebhookDeliveryView>>> ListDeliveriesAsync(
        Guid endpointId, int limit, string? cursor, CancellationToken cancellationToken)
    {
        limit = PageLimit.Clamp(limit);
        if (!TryDecodeCursor(cursor, out var after))
        {
            return Result.Failure<CursorPage<WebhookDeliveryView>>(CursorMalformed);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // A cross-tenant or unknown endpoint id is invisible under RLS: collapse to 404
        // rather than returning an empty page that confirms nothing.
        var endpointExists = await db.WebhookEndpoints.AnyAsync(
            endpoint => endpoint.Id == endpointId, cancellationToken);
        if (!endpointExists)
        {
            return Result.Failure<CursorPage<WebhookDeliveryView>>(EndpointNotFound);
        }

        var query = db.WebhookDeliveries.AsNoTracking().Where(delivery => delivery.EndpointId == endpointId);
        if (after is { } key)
        {
            query = query.Where(delivery =>
                delivery.CreatedAt < key.CreatedAt
                || (delivery.CreatedAt == key.CreatedAt && delivery.Id.CompareTo(key.Id) < 0));
        }

        var rows = await query
            .OrderByDescending(delivery => delivery.CreatedAt)
            .ThenByDescending(delivery => delivery.Id)
            .Take(limit + 1)
            .Select(delivery => new WebhookDeliveryView(
                delivery.Id,
                delivery.EndpointId,
                delivery.EventId,
                delivery.EventType,
                delivery.Status,
                delivery.Attempts,
                delivery.NextAttemptAt,
                delivery.DeliveredAt,
                delivery.DeadLetteredAt,
                delivery.LastResponseStatus,
                delivery.LastError,
                delivery.CreatedAt))
            .ToListAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = new KeysetCursor(lastKept.CreatedAt, lastKept.Id).Encode();
            rows.RemoveAt(rows.Count - 1);
        }

        return new CursorPage<WebhookDeliveryView>(rows, nextCursor);
    }

    public async Task<Result> ReplayDeliveryAsync(Guid deliveryId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var delivery = await db.WebhookDeliveries.SingleOrDefaultAsync(
            candidate => candidate.Id == deliveryId, cancellationToken);
        if (delivery is null)
        {
            return Result.Failure(DeliveryNotFound);
        }

        // Reset a delivered, failed, or dead delivery to pending so the worker re-sends the
        // stored body (webhooks.md section 7).
        delivery.Status = WebhookDeliveryStatus.Pending;
        delivery.Attempts = 0;
        delivery.NextAttemptAt = now;
        delivery.DeliveredAt = null;
        delivery.DeadLetteredAt = null;
        delivery.LastResponseStatus = null;
        delivery.LastError = null;
        await db.SaveChangesAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private async Task<Result<string>> ValidateUrlAsync(string? url, CancellationToken cancellationToken)
    {
        var trimmed = url?.Trim();
        if (string.IsNullOrEmpty(trimmed) || !Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return Result.Failure<string>(new Error(
                ErrorKind.Validation, "webhooks.url_invalid", "The webhook URL must be an absolute https URL."));
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return Result.Failure<string>(new Error(
                ErrorKind.Validation, "webhooks.url_invalid", "The webhook URL must use https."));
        }

        // Fast-fail range check (an obviously-internal literal target is rejected up
        // front); connect-time is the authoritative guard, so a host that does not
        // resolve now is allowed (it may resolve public later).
        try
        {
            var addresses = await resolver.ResolveAsync(uri.Host, cancellationToken);
            foreach (var address in addresses)
            {
                if (WebhookAddressGuard.IsBlocked(address, _options.AllowLoopbackDelivery))
                {
                    return Result.Failure<string>(new Error(
                        ErrorKind.Validation,
                        "webhooks.url_blocked",
                        "The webhook URL resolves to a blocked (non-public) address."));
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Resolution failed now; the connect-time guard is authoritative.
        }

        return trimmed;
    }

    private static Result<string[]> NormalizeEventTypes(IReadOnlyList<string>? eventTypes)
    {
        if (eventTypes is null)
        {
            return Array.Empty<string>();
        }

        var normalized = eventTypes
            .Select(type => type?.Trim() ?? string.Empty)
            .Where(type => type.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length > MaxEventTypes)
        {
            return Result.Failure<string[]>(new Error(
                ErrorKind.Validation,
                "webhooks.too_many_event_types",
                $"An endpoint may subscribe to at most {MaxEventTypes} event types."));
        }

        return normalized;
    }

    private static string NormalizeDescription(string? description)
    {
        var trimmed = (description ?? string.Empty).Trim();
        return trimmed.Length > MaxDescriptionLength ? trimmed[..MaxDescriptionLength] : trimmed;
    }

    private static bool TryDecodeCursor(string? cursor, out KeysetCursor? after)
    {
        after = null;
        if (string.IsNullOrEmpty(cursor))
        {
            return true;
        }

        if (!KeysetCursor.TryDecode(cursor, out var decoded))
        {
            return false;
        }

        after = decoded;
        return true;
    }

    private static readonly Error EndpointNotFound = new(
        ErrorKind.NotFound, "webhooks.endpoint_not_found", "No such webhook endpoint.");

    private static readonly Error DeliveryNotFound = new(
        ErrorKind.NotFound, "webhooks.delivery_not_found", "No such webhook delivery.");

    private static readonly Error CursorMalformed = new(
        ErrorKind.Validation, "webhooks.cursor_malformed", "The pagination cursor is malformed.");
}
