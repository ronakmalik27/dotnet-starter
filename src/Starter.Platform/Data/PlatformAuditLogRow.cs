namespace Starter.Platform.Data;

/// <summary>
/// A platform.platform_audit_log row: one platform-staff action that is not
/// scoped to any one tenant - granting or revoking a super-admin (audit-log.md
/// section 4). This is the enterprise/organization-trail counterpart to the
/// per-tenant <see cref="AuditLogRow"/>, readable only through the super-admin
/// plane.
/// <para>
/// It is NOT tenant-owned and carries NO row-level security, consistent with
/// every other platform table: it is written only on the bypass path (in the
/// same transaction as the grant/revoke it records, through
/// <see cref="IPlatformAuditWriter"/>) and read only behind RequirePlatformAdmin,
/// so it never needs a <c>tenant_id</c>. The request role has NO privilege on it
/// at all (REVOKE ALL at boot, audit-log.md section 8), so request-scoped SQL can
/// neither see nor forge the platform audit trail.
/// </para>
/// </summary>
internal sealed class PlatformAuditLogRow
{
    /// <summary>Primary key; equals the source domain event id.</summary>
    public required Guid Id { get; init; }

    /// <summary>When the action happened.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>When the row was written.</summary>
    public required DateTimeOffset RecordedAt { get; init; }

    /// <summary>The event type, e.g. <c>platform.admin.granted</c>.</summary>
    public required string Action { get; init; }

    /// <summary>The platform staff member who acted.</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>The user the action was about.</summary>
    public Guid? SubjectUserId { get; init; }

    /// <summary>A short, bounded, non-PII rendering of the action.</summary>
    public required string Summary { get; init; }

    /// <summary>The event payload verbatim (jsonb): ids and scalars only.</summary>
    public required string Data { get; init; }
}
