using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.scim_tokens row: one tenant's SCIM bearer credential
/// (sso-and-scim.md section 5). Tenant-owned in the ordinary way (a real tenant_id
/// column, the RLS discriminator), so listing a tenant's SCIM tokens is an ordinary
/// tenant-scoped read and one tenant can never see another's.
/// <para>
/// The token is a bearer secret stored only as a hash, shown once at create and
/// rotate: <see cref="TokenHash"/> is the SHA-256 hex of the raw <c>scim_</c>-prefixed
/// token (globally UNIQUE, since the resolve is tenant-less - the API-key pattern) and
/// <see cref="TokenPrefix"/> is the first chars of the raw token in clear for display.
/// A token past <see cref="ExpiresAt"/> or with <see cref="RevokedAt"/> set fails to
/// resolve on the next request - every miss collapsing to one indistinguishable null.
/// </para>
/// </summary>
internal sealed class ScimToken : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>
    /// SHA-256 hex of the raw SCIM token: the tenant-less lookup key, globally unique.
    /// Replaced on rotate. <see cref="SensitiveAttribute"/>: a credential column that
    /// must never appear in a data export or the operator erasure snapshot
    /// (data-export-and-erasure.md section 8).
    /// </summary>
    [Sensitive]
    public required string TokenHash { get; set; }

    /// <summary>The first chars of the raw token, in clear for display. Never the secret. Replaced on rotate.</summary>
    public required string TokenPrefix { get; set; }

    /// <summary>The admin (or owner) who created the token. A bare id by value, no cross-schema FK.</summary>
    public required Guid CreatedBy { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Optional expiry; a token past it fails to resolve. Null means no expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Set on rotate/revoke; a revoked token fails to resolve. Un-revoke is not offered (mint a new token).</summary>
    public DateTimeOffset? RevokedAt { get; set; }
}
