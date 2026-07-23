namespace Starter.Identity.Domain;

/// <summary>
/// An identity.mfa_credentials row, one per user (mfa-totp.md section 2). A
/// global-user credential like the password (no tenant, no RLS), keyed by
/// user_id. The TOTP shared secret must be recoverable to verify a code, so
/// it is encrypted at rest with the DataProtection key ring - never hashed,
/// never clear. MFA is enforced at login only when <see cref="ConfirmedAt"/>
/// is set.
/// </summary>
internal sealed class MfaCredential
{
    /// <summary>The owning user; also the primary key (one enrollment per user).</summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// The active TOTP shared secret, base32 then DataProtection-encrypted
    /// (the <c>identity.mfa.secret.v1</c> protector). Verified against at
    /// login once <see cref="ConfirmedAt"/> is set.
    /// </summary>
    public required string SecretEncrypted { get; set; }

    /// <summary>
    /// A re-enrollment's not-yet-confirmed secret, DataProtection-encrypted,
    /// held here so a half-finished re-enroll never disturbs the ACTIVE
    /// secret or its confirmed state (mfa-totp.md section 4). Null when no
    /// re-enroll is pending. Promoted into <see cref="SecretEncrypted"/> on a
    /// successful confirm. For the very first enrollment the pending secret
    /// lives in <see cref="SecretEncrypted"/> with <see cref="ConfirmedAt"/>
    /// null instead, so this stays null until the account is already confirmed.
    /// </summary>
    public string? PendingSecretEncrypted { get; set; }

    /// <summary>
    /// Null = enrollment begun but not confirmed (MFA NOT enforced yet); set
    /// on the first valid code. Only a non-null value gates login.
    /// </summary>
    public DateTimeOffset? ConfirmedAt { get; set; }

    /// <summary>
    /// The last time-step a code was accepted for: the replay guard
    /// (mfa-totp.md section 3). A code whose step is &lt;= this is rejected,
    /// so each step is single-use even within its validity window.
    /// </summary>
    public long? LastStep { get; set; }

    /// <summary>
    /// Consecutive failed verify attempts (mfa-totp.md section 5), the same
    /// lockout idiom the password path uses. Incremented on a wrong code,
    /// reset to 0 on a successful verify. A fresh challenge does not reset it.
    /// </summary>
    public int FailedAttempts { get; set; }

    /// <summary>
    /// When the MFA verify step is locked until, or null when it is not
    /// locked. Set when <see cref="FailedAttempts"/> crosses the platform
    /// lockout threshold; auto-unlock is implicit (locked_until &lt;= now).
    /// </summary>
    public DateTimeOffset? LockedUntil { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}
