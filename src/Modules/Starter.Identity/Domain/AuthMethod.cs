namespace Starter.Identity.Domain;

/// <summary>
/// An identity.auth_methods row: credentials are a list per account, not
/// columns on the user row (FR-AUTH-15 deferred-readiness hook; doc 07
/// section 4). kind=password landed with #33; kind=google with #35.
/// </summary>
internal sealed class AuthMethod
{
    public required Guid Id { get; init; }

    public required Guid UserId { get; init; }

    public required string Kind { get; init; }

    /// <summary>
    /// Argon2id hash in PHC string format, parameters per-hash so
    /// rehash-on-login can move them (doc 10 4.1). Null for non-password
    /// kinds.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>The OIDC subject for kind=google (#35); null for password.</summary>
    public string? ProviderSubject { get; init; }

    /// <summary>
    /// Set when the method is disabled without being deleted. Today only
    /// the SRS 5.3 claim path writes it: an OIDC-verified email claiming an
    /// unverified password account disables password login until a reset
    /// (FR-AUTH-05) stores a fresh hash and clears this. The row survives
    /// so the claim is auditable and reversible (doc 07 section 4).
    /// </summary>
    public DateTimeOffset? DisabledAt { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>auth_methods.kind values (doc 07 section 4).</summary>
internal static class AuthMethodKind
{
    public const string Password = "password";

    public const string Google = "google";
}
