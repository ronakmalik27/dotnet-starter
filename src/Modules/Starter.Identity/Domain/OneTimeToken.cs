namespace Starter.Identity.Domain;

/// <summary>
/// An identity.one_time_tokens row: one table for every
/// single-use emailed token, discriminated by purpose. Single-use is
/// enforced by used_at (set atomically at consumption, never cleared);
/// expiry by expires_at. The raw token exists only in transit - the row
/// stores a SHA-256 hex digest, same rule as sessions.refresh_hash
/// (stored hashed).
/// </summary>
internal sealed class OneTimeToken
{
    public required Guid Id { get; init; }

    public required Guid UserId { get; init; }

    /// <summary>One of the <see cref="OneTimeTokenPurpose"/> values.</summary>
    public required string Purpose { get; init; }

    /// <summary>SHA-256 of the 256-bit random token, lowercase hex.</summary>
    public required string TokenHash { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set exactly once at consumption; never cleared.</summary>
    public DateTimeOffset? UsedAt { get; set; }

    /// <summary>
    /// Purpose-specific JSON payload (revert_email
    /// carries its revert data here). Null for verify_email.
    /// </summary>
    public string? Payload { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// one_time_tokens.purpose values (the schema owns the full enum:
/// verify_email / reset_password / change_email / revert_email). Only
/// verify_email is in play this story; the reset and
/// email-change flows add their constants with their stories - the
/// purpose-discriminated table already accommodates them.
/// </summary>
internal static class OneTimeTokenPurpose
{
    public const string VerifyEmail = "verify_email";
}
