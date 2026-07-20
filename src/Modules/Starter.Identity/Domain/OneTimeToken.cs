namespace Starter.Identity.Domain;

/// <summary>
/// An identity.one_time_tokens row (doc 07 section 4): one table for every
/// single-use emailed token, discriminated by purpose. Single-use is
/// enforced by used_at (set atomically at consumption, never cleared);
/// expiry by expires_at. The raw token exists only in transit - the row
/// stores a SHA-256 hex digest, same rule as sessions.refresh_hash
/// (doc 10 4.4: stored hashed).
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
    /// Purpose-specific JSON payload (doc 07 section 4: revert_email
    /// carries the FR-AUTH-09 revert data here). Null for verify_email.
    /// </summary>
    public string? Payload { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// one_time_tokens.purpose values (doc 07 section 4 owns the full enum:
/// verify_email / reset_password / change_email / revert_email). Only
/// verify_email is in play this story (#34); the reset (#38-era) and
/// email-change flows add their constants with their stories - the
/// purpose-discriminated table already accommodates them.
/// </summary>
internal static class OneTimeTokenPurpose
{
    public const string VerifyEmail = "verify_email";
}
