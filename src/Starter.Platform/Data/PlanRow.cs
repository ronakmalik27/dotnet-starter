namespace Starter.Platform.Data;

/// <summary>
/// A platform.plans row: one operator-owned catalogue entry
/// (billing-and-entitlements.md section 2). A plan is a price tier mapped to an
/// entitlement set - the features it includes, the RBAC permissions a custom role
/// on it may hold, and its numeric limits. The catalogue is global (no
/// <c>tenant_id</c>), like the permission catalogue and the platform-admin roster,
/// so this is a no-RLS platform table read on both paths and written only on the
/// bypass path (the super-admin plane).
/// <para>
/// <see cref="Features"/> and <see cref="Permissions"/> are NULLABLE arrays with a
/// deliberate semantics: SQL NULL means the plan restricts NOTHING (unrestricted),
/// while a non-null array (even empty) is CLOSED to exactly that set. This is the
/// opposite of an empty array, so the seeded default plan stores NULL, not
/// <c>{}</c> - a mistaken <c>{}</c> would strip every feature and grantable
/// permission from every tenant at once.
/// </para>
/// <para>
/// EF maps this so the migration generates the table and the request path reads it
/// through the DbSet; the super-admin CRUD writes it with raw SQL on the bypass
/// path (the same shape the platform-admin roster uses), which is also how the
/// nullable arrays are written as SQL NULL rather than <c>{}</c>.
/// </para>
/// </summary>
internal sealed class PlanRow
{
    /// <summary>Primary key; the value stored in <c>tenant.plan</c> (e.g. <c>free</c>, <c>pro</c>).</summary>
    public required string Key { get; init; }

    /// <summary>Display name.</summary>
    public required string Name { get; init; }

    /// <summary>The feature keys this plan INCLUDES; NULL = unrestricted (all features).</summary>
    public string[]? Features { get; init; }

    /// <summary>The RBAC permission atoms a custom role on this plan may hold; NULL = unrestricted (section 4a).</summary>
    public string[]? Permissions { get; init; }

    /// <summary>Numeric limits as jsonb, e.g. <c>{ "seatLimit": 5 }</c>. Stored verbatim; parsed on resolve.</summary>
    public required string Limits { get; init; }

    /// <summary>The plan a new tenant gets; exactly one is true (a partial unique index enforces it).</summary>
    public required bool IsDefault { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}
