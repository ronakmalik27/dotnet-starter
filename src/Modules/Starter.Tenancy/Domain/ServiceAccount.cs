using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.service_accounts row: a non-human principal that authenticates with
/// a hashed API key and carries scoped RBAC grants, not a membership
/// (service-accounts.md sections 1, 5). Tenant-owned in the ordinary way (a real
/// tenant_id column, the RLS discriminator and the query-filter key), so listing
/// service accounts is an ordinary tenant-scoped read and one tenant can never
/// see another's.
/// <para>
/// The row's <see cref="Id"/> is also the grant principal_id
/// (principal_type = service_account). The key is a bearer secret stored only as
/// a hash, shown once at create and rotate: <see cref="KeyHash"/> is the SHA-256
/// hex of the raw key (globally UNIQUE, since the resolve is tenant-less) and
/// <see cref="KeyPrefix"/> is the first chars of the raw key in clear for display.
/// A key past <see cref="ExpiresAt"/> or with <see cref="RevokedAt"/> set fails to
/// resolve on the next request.
/// </para>
/// </summary>
internal sealed class ServiceAccount : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>The admin-facing label. Editable is a documented extension; fixed at create today.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// SHA-256 hex of the raw key: the tenant-less lookup key, globally unique. Replaced
    /// on rotate. <see cref="SensitiveAttribute"/>: a credential column that must never
    /// appear in a data export or the operator erasure snapshot
    /// (data-export-and-erasure.md section 8).
    /// </summary>
    [Sensitive]
    public required string KeyHash { get; set; }

    /// <summary>The first chars of the raw key, in clear for display. Never the secret. Replaced on rotate.</summary>
    public required string KeyPrefix { get; set; }

    /// <summary>The admin (or owner) who created the account. A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Approximate last-active instant, throttled (service-accounts.md section 6). Null until first used.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>Optional expiry; a key past it fails to resolve. Null means no expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Set on revoke; a revoked key fails to resolve. Un-revoke is not offered (mint a new account).</summary>
    public DateTimeOffset? RevokedAt { get; set; }
}
