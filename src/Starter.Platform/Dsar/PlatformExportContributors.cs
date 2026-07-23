using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Starter.Platform.Data;

namespace Starter.Platform.Dsar;

/// <summary>
/// The Platform module's export contributors (data-export-and-erasure.md section 3):
/// the tenant-owned platform tables - the audit log, webhook endpoints (secret
/// EXCLUDED) and their deliveries, usage counters, and feature-flag overrides. Each
/// reads the request-scoped, RLS-bound <see cref="PlatformDbContext"/> inside a
/// transaction (the interceptor sets the tenant GUC on transaction start), so a
/// contributor only ever sees the ACTIVE tenant's rows. NO bypass anywhere.
/// </summary>
internal static class PlatformExportContributors
{
    /// <summary>The audit log (audit-log.md): the tenant's "who did what" trail, payloads as parsed JSON.</summary>
    internal sealed class AuditLog(PlatformDbContext db) : IDataExportContributor
    {
        public string Section => "auditLog";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.AuditLog
                .AsNoTracking()
                .OrderBy(row => row.OccurredAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.OccurredAt,
                    row.RecordedAt,
                    row.Action,
                    row.ActorUserId,
                    row.EntityId,
                    row.Summary,
                    row.Data,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return rows
                .Select(row => new
                {
                    row.Id,
                    row.OccurredAt,
                    row.RecordedAt,
                    row.Action,
                    row.ActorUserId,
                    row.EntityId,
                    row.Summary,
                    Data = Json(row.Data),
                })
                .ToList();
        }
    }

    /// <summary>Webhook endpoints (webhooks.md): the encrypted signing secret is EXCLUDED (section 8); the display prefix stays.</summary>
    internal sealed class WebhookEndpoints(PlatformDbContext db) : IDataExportContributor
    {
        public string Section => "webhookEndpoints";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.WebhookEndpoints
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Url,
                    row.Description,
                    row.EventTypes,
                    // SigningSecretEncrypted is deliberately absent (a [Sensitive]
                    // credential column, section 8); the display prefix is not a secret.
                    row.SecretPrefix,
                    row.DisabledAt,
                    row.CreatedBy,
                    row.CreatedAt,
                    row.UpdatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return rows;
        }
    }

    /// <summary>Webhook deliveries (webhooks.md): one row per (event, endpoint), the delivered body as parsed JSON.</summary>
    internal sealed class WebhookDeliveries(PlatformDbContext db) : IDataExportContributor
    {
        public string Section => "webhookDeliveries";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.WebhookDeliveries
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.EndpointId,
                    row.EventId,
                    row.EventType,
                    row.Payload,
                    row.Status,
                    row.Attempts,
                    row.DeliveredAt,
                    row.DeadLetteredAt,
                    row.LastResponseStatus,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return rows
                .Select(row => new
                {
                    row.Id,
                    row.EndpointId,
                    row.EventId,
                    row.EventType,
                    Payload = Json(row.Payload),
                    row.Status,
                    row.Attempts,
                    row.DeliveredAt,
                    row.DeadLetteredAt,
                    row.LastResponseStatus,
                    row.CreatedAt,
                })
                .ToList();
        }
    }

    /// <summary>Metered usage counters (quotas.md): the tenant's consumption per metric per period.</summary>
    internal sealed class UsageCounters(PlatformDbContext db) : IDataExportContributor
    {
        public string Section => "usageCounters";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.UsageCounters
                .AsNoTracking()
                .OrderBy(row => row.Metric)
                .ThenBy(row => row.PeriodStart)
                .Select(row => new
                {
                    row.Metric,
                    row.PeriodStart,
                    row.Used,
                    row.UpdatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return rows;
        }
    }

    /// <summary>The tenant's feature-flag overrides (feature-flags.md).</summary>
    internal sealed class FeatureFlagOverrides(PlatformDbContext db) : IDataExportContributor
    {
        public string Section => "featureFlagOverrides";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.FeatureFlagOverrides
                .AsNoTracking()
                .OrderBy(row => row.FlagKey)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.FlagKey,
                    row.ScopeType,
                    row.ScopeId,
                    row.Enabled,
                    row.SetBy,
                    row.UpdatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return rows;
        }
    }

    // A jsonb column is stored as text; parse it so it exports as structured JSON,
    // not a doubly-encoded string. A malformed value (never expected for a catalogue
    // payload) falls back to the raw string rather than throwing.
    private static JsonNode? Json(string value)
    {
        try
        {
            return JsonNode.Parse(value);
        }
        catch (System.Text.Json.JsonException)
        {
            return JsonValue.Create(value);
        }
    }
}
