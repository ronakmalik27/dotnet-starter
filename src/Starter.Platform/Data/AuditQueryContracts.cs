namespace Starter.Platform.Data;

/// <summary>
/// The shared audit-read filter (audit-log.md section 6): the tenant-admin read
/// and the super-admin read take the same shape. All fields are optional; the
/// keyset cursor <see cref="Before"/> positions on <c>(occurred_at, id)</c>, the
/// same pagination contract the other list endpoints use.
/// </summary>
/// <param name="Actor">Filter to one actor user id.</param>
/// <param name="Action">
/// Exact match, or a dotted prefix (ending in a '.', e.g. <c>tenancy.member.</c>
/// matches all membership actions).
/// </param>
/// <param name="Entity">Filter to one entity (subject) id.</param>
/// <param name="From">Inclusive lower bound on occurred_at.</param>
/// <param name="To">Exclusive upper bound on occurred_at.</param>
/// <param name="Limit">Page size (clamped to the shared PageLimit bounds).</param>
/// <param name="Before">Opaque keyset cursor for the next (older) page.</param>
public sealed record AuditQueryFilter(
    Guid? Actor,
    string? Action,
    Guid? Entity,
    DateTimeOffset? From,
    DateTimeOffset? To,
    int? Limit,
    string? Before);

/// <summary>One tenant-audit entry (audit-log.md section 3).</summary>
public sealed record AuditEntry(
    Guid Id,
    Guid TenantId,
    DateTimeOffset OccurredAt,
    DateTimeOffset RecordedAt,
    string Action,
    Guid? ActorUserId,
    Guid? EntityId,
    string Summary,
    string Data);

/// <summary>One platform-audit entry (audit-log.md section 4).</summary>
public sealed record PlatformAuditEntry(
    Guid Id,
    DateTimeOffset OccurredAt,
    DateTimeOffset RecordedAt,
    string Action,
    Guid? ActorUserId,
    Guid? SubjectUserId,
    string Summary,
    string Data);

/// <summary>A page of audit entries plus the opaque cursor for the next (older) page.</summary>
/// <typeparam name="T">The entry type (<see cref="AuditEntry"/> or <see cref="PlatformAuditEntry"/>).</typeparam>
public sealed record AuditPage<T>(IReadOnlyList<T> Items, string? NextCursor);
