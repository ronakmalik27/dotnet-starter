using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// A platform.audit_log row: one audited domain event, projected from the outbox
/// by <c>AuditProjectionConsumer</c> (audit-log.md section 3). It is the queryable
/// "who did what, to what, and when, in my tenant" trail - a projection distinct
/// from the raw event spine, the industry-standard shape (Stripe, GitHub, AWS
/// CloudTrail).
/// <para>
/// It is the FIRST and only <see cref="ITenantOwned"/> table in the platform
/// schema: it carries <c>tenant_id</c> and lives under FORCE row-level security,
/// so a tenant admin reading their audit log is bound by the same authoritative
/// boundary as every other tenant read (audit-log.md section 9). The natural key
/// is the source event id, which makes the projection idempotent under the
/// outbox's at-least-once delivery (a redelivery is a primary-key no-op). Rows are
/// inserted, never updated or deleted by the application; the request role's DML
/// is REVOKED down to select + insert at boot (audit-log.md section 8).
/// </para>
/// </summary>
internal sealed class AuditLogRow : ITenantOwned
{
    /// <summary>Primary key; equals the source domain event id (idempotent projection).</summary>
    public required Guid Id { get; init; }

    /// <summary>The RLS discriminator, stamped from the event's tenant on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>When the action happened (the event's occurred_at).</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>When the projection wrote this row (Clock.UtcNow at consume time).</summary>
    public required DateTimeOffset RecordedAt { get; init; }

    /// <summary>The event type, e.g. <c>tenancy.member.role_changed</c>.</summary>
    public required string Action { get; init; }

    /// <summary>The event's actor, or null for a system action.</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>The event's primary subject id.</summary>
    public Guid? EntityId { get; init; }

    /// <summary>A short, bounded, non-PII rendering of the action.</summary>
    public required string Summary { get; init; }

    /// <summary>The event payload verbatim (jsonb): ids and scalars only, never PII.</summary>
    public required string Data { get; init; }
}
