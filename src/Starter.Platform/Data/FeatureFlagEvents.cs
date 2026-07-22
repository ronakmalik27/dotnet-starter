using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The tenant feature-flag override events (feature-flags.md section 5). These are
/// tenant-scoped <c>tenancy.feature_flag.*</c> events, but the feature lives in
/// Platform (which cannot reference the Tenancy module), so the factories are defined
/// here next to the Platform-registered override service that emits them - exactly
/// like <c>WebhookEvents</c>. <c>OutboxWriter</c> stamps <c>tenant_id</c> from the
/// tenant the enqueue runs under (the RLS-bound request context), so each row lands
/// scoped to the acting tenant.
/// <para>
/// Payloads carry the flag key, the scope, and (for a set) the value - ids and
/// scalars only, never PII. Both are on the shared deliverable catalogue, so an
/// override change is audited AND webhook-deliverable.
/// </para>
/// </summary>
internal static class FeatureFlagEvents
{
    private const string Module = "tenancy";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>tenancy.feature_flag.override_set: a tenant set or changed a flag override at tenant or workspace scope.</summary>
    public const string OverrideSetType = "tenancy.feature_flag.override_set";

    /// <summary>tenancy.feature_flag.override_cleared: a tenant cleared a flag override, falling back to the layer below.</summary>
    public const string OverrideClearedType = "tenancy.feature_flag.override_cleared";

    // Each factory constructs its record inline (rather than through a shared helper):
    // the catalogue-completeness test reflects over EVERY static method returning
    // DomainEventRecord on a *Events type, so a shared helper would be invoked as a
    // "factory" with a null event type. Keeping only the literal-typed factories keeps
    // the reflection scan honest.

    public static DomainEventRecord OverrideSet(
        string flagKey,
        string scopeType,
        Guid? scopeId,
        bool enabled,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = OverrideSetType,
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { flagKey, scopeType, scopeId, enabled }, Json),
        };

    public static DomainEventRecord OverrideCleared(
        string flagKey,
        string scopeType,
        Guid? scopeId,
        Guid actorUserId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = OverrideClearedType,
            EntityId = Guid.Empty,
            ActorUserId = actorUserId,
            Payload = JsonSerializer.Serialize(new { flagKey, scopeType, scopeId }, Json),
        };
}
