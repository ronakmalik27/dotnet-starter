namespace Starter.Identity.Domain;

/// <summary>
/// An identity.auth_methods row: credentials are a list per account, not
/// columns on the user row (a deferred-readiness hook). kind=password
/// landed first; kind=google followed.
/// </summary>
internal sealed class AuthMethod
{
    public required Guid Id { get; init; }

    public required Guid UserId { get; init; }

    public required string Kind { get; init; }

    /// <summary>
    /// Argon2id hash in PHC string format, parameters per-hash so
    /// rehash-on-login can move them. Null for non-password
    /// kinds.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>The OIDC subject for kind=google; null for password.</summary>
    public string? ProviderSubject { get; init; }

    /// <summary>
    /// Set when the method is disabled without being deleted. Today only
    /// the account-linking claim path writes it: an OIDC-verified email claiming an
    /// unverified password account disables password login until a reset
    /// stores a fresh hash and clears this. The row survives
    /// so the claim is auditable and reversible.
    /// </summary>
    public DateTimeOffset? DisabledAt { get; set; }

    /// <summary>
    /// Consecutive failed password attempts (role-templates-and-policy-defaults.md
    /// section 4). Incremented on a wrong password, reset to 0 on a successful
    /// verify. Only the kind=password row carries lockout state; Google-OIDC has no
    /// password credential, so it is never locked.
    /// </summary>
    public int FailedAttempts { get; set; }

    /// <summary>
    /// When the password credential is locked until, or null when it is not locked.
    /// Set when <see cref="FailedAttempts"/> crosses the platform lockout threshold;
    /// auto-unlock is implicit (once <c>locked_until &lt;= now</c> a fresh attempt is
    /// allowed again), so no unlock job is needed.
    /// </summary>
    public DateTimeOffset? LockedUntil { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>auth_methods.kind values.</summary>
internal static class AuthMethodKind
{
    public const string Password = "password";

    public const string Google = "google";
}
