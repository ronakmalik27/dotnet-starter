namespace Starter.Platform.Data;

/// <summary>
/// A platform.platform_admins row: one cross-tenant operator (multi-tenancy.md
/// sections 6 and 7). Platform power is deliberately separate from tenant
/// membership - it is presence in this table, never a tenant role - so a tenant
/// owner is not a platform admin and vice versa. The table carries NO row-level
/// security; it is administered only on the bypass path. The first admin is an
/// out-of-band seed (config-driven at startup), never self-granted through the
/// API.
/// <para>
/// EF maps this so the migration generates the table; the runtime reads and
/// writes it through raw SQL on the bypass data source (the same shape the
/// membership directory and invitation acceptor use), never through this
/// DbSet, so no request-scoped context can reach it.
/// </para>
/// </summary>
internal sealed class PlatformAdminRow
{
    /// <summary>The operator's global user id (identity.users by value, no cross-schema FK). Primary key.</summary>
    public required Guid UserId { get; init; }

    /// <summary>The admin who granted this one, or null for the out-of-band bootstrap seed.</summary>
    public Guid? GrantedBy { get; init; }

    public required DateTimeOffset GrantedAt { get; init; }
}
