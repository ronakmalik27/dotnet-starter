using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.tenants row: one tenant boundary. It is <see cref="ITenantOwned"/>,
/// but uniquely among tenant-owned entities its OWN id is the tenant
/// discriminator - a tenant row is visible only under its own id - so
/// <see cref="TenantId"/> returns <see cref="Id"/> and the RLS policy keys on
/// id, not a separate tenant_id column (there is none). Soft-delete via status;
/// the row is never hard-deleted (audit). Created and administered on the bypass
/// path, since establishing a boundary necessarily precedes any tenant context.
/// </summary>
internal sealed class Tenant : ITenantOwned
{
    public required Guid Id { get; init; }

    /// <summary>
    /// The tenant discriminator IS the primary key. Not a stored column (the
    /// mapping ignores it); the query filter keys on <see cref="Id"/> directly.
    /// </summary>
    public Guid TenantId => Id;

    /// <summary>
    /// Case-insensitive unique (citext), caller-supplied at signup and settable
    /// by a tenant-admin settings update (the citext unique index guards a
    /// collision).
    /// </summary>
    public required string Slug { get; set; }

    public required string Name { get; set; }

    /// <summary>One of active | suspended | deleted (stored as a string).</summary>
    public required string Status { get; set; }

    /// <summary>
    /// The billing plan, e.g. "free". Nullable. Settable (like <see cref="Status"/>)
    /// so the super-admin assign-plan path can move a tenant between plans
    /// (billing-and-entitlements.md section 7).
    /// </summary>
    public string? Plan { get; set; }

    /// <summary>
    /// The seat limit, denormalized from the assigned plan's <c>seatLimit</c>
    /// (billing-and-entitlements.md section 5). Settable so assign-plan keeps it in
    /// sync with the plan; the race-proof seat check in invitation-accept keeps
    /// reading it off the locked tenant row unchanged.
    /// </summary>
    public int SeatLimit { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The user who created the tenant (the first owner). A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    /// <summary>
    /// When the tenant was soft-deleted (status -&gt; deleted), or null while it is
    /// active or suspended (data-export-and-erasure.md section 2). Stamped on
    /// soft-delete (both the super-admin and owner paths), cleared on reactivate. The
    /// retention window (<c>DsarOptions.RetentionDays</c>) is measured from it: a hard
    /// delete is permitted only once <c>deleted_at + RetentionDays &lt;= now</c> (or a
    /// break-glass force).
    /// </summary>
    public DateTimeOffset? DeletedAt { get; set; }
}

/// <summary>tenancy.tenants.status values (the schema owns the full set).</summary>
internal static class TenantStatus
{
    public const string Active = "active";

    public const string Suspended = "suspended";

    public const string Deleted = "deleted";
}
