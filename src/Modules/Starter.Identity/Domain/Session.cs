namespace Starter.Identity.Domain;

/// <summary>
/// An identity.sessions row. Rotation writes a NEW row
/// per refresh within the same family; the superseded row keeps its
/// revoked_at, so a rotated token presented again is detectable reuse and
/// revokes the whole family.
/// </summary>
internal sealed class Session
{
    public required Guid Id { get; init; }

    public required Guid UserId { get; init; }

    /// <summary>Constant across rotations; the unit of reuse revocation.</summary>
    public required Guid FamilyId { get; init; }

    /// <summary>
    /// SHA-256 of the 256-bit random refresh token, lowercase hex. The raw
    /// token exists only in transit (stored hashed).
    /// </summary>
    public required string RefreshHash { get; init; }

    /// <summary>
    /// The user's token version when this row was issued; refresh rejects
    /// on mismatch (ver enforced at refresh only).
    /// </summary>
    public required int TokenVersion { get; init; }

    public string? DeviceLabel { get; init; }

    public string? Ip { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset LastActiveAt { get; set; }

    /// <summary>Set on rotation, logout, or family revocation; never cleared.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>The family's absolute deadline; rotation never extends it.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
