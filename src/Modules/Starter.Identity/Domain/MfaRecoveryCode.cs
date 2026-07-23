namespace Starter.Identity.Domain;

/// <summary>
/// An identity.mfa_recovery_codes row (mfa-totp.md section 6): the
/// lost-authenticator escape hatch. High-entropy, one-time, and stored ONLY
/// as a SHA-256 hex digest (the API-key hashing discipline) - the code itself
/// is shown once at generation and never persisted. A used code
/// (<see cref="UsedAt"/> set) never works again; consumption is a single
/// atomic conditional update.
/// </summary>
internal sealed class MfaRecoveryCode
{
    public required Guid Id { get; init; }

    public required Guid UserId { get; init; }

    /// <summary>SHA-256 hex of the normalized recovery code; the code is never stored clear.</summary>
    public required string CodeHash { get; init; }

    /// <summary>Set exactly once when the code is consumed; a used code never verifies again.</summary>
    public DateTimeOffset? UsedAt { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}
