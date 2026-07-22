namespace Starter.Platform.Data;

/// <summary>
/// A platform.impersonation_grants row: the audit spine for one impersonation
/// session (multi-tenancy.md section 7). The row and the ImpersonationStarted
/// event are written in one transaction, so no impersonation token can exist
/// without its audit record. Every imp-bearing request re-checks the row
/// (ended_at IS NULL AND now() &lt; expires_at), so ending a session takes
/// effect immediately, not only at token expiry. The table carries NO row-level
/// security; it is written and read only on the bypass path.
/// <para>
/// EF maps this so the migration generates the table (and its listing indexes);
/// the runtime writes and reads it through raw SQL on the bypass data source,
/// never through this DbSet.
/// </para>
/// </summary>
internal sealed class ImpersonationGrantRow
{
    public required Guid Id { get; init; }

    /// <summary>The acting platform admin (attributable, unforgeable via the signed imp claim).</summary>
    public required Guid PlatformAdminUserId { get; init; }

    /// <summary>The tenant the session is scoped to (may be suspended - a support use case).</summary>
    public required Guid TargetTenantId { get; init; }

    /// <summary>The user being acted as, or null when the admin acts as themselves in the tenant.</summary>
    public Guid? TargetUserId { get; init; }

    /// <summary>The written reason (required, non-empty). Free text, never a secret.</summary>
    public required string Reason { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>Absolute expiry: min(configured window, the 15-minute access cap). The token's exp equals this.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>When the session was ended early, or null while it is live.</summary>
    public DateTimeOffset? EndedAt { get; set; }
}
