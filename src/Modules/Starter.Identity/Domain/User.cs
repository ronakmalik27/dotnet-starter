namespace Starter.Identity.Domain;

/// <summary>
/// An identity.users row - only the columns the landed flows need:
/// the auth columns plus the verification pair;
/// deletion and placeholder columns join with their stories.
/// </summary>
internal sealed class User
{
    public required Guid Id { get; init; }

    /// <summary>
    /// Case-insensitive unique (citext). Non-null for
    /// self-registered accounts; the placeholder story relaxes this later.
    /// </summary>
    public required string Email { get; init; }

    public required string Status { get; set; }

    /// <summary>
    /// When the address was proven. The verify_email
    /// token flow sets it for password registrations (the `vrf`
    /// capability gate reads exactly this); Google sign-in sets it
    /// directly, but only after validating that the OIDC ID token's
    /// `email_verified` claim is `true` - signing in with Google alone
    /// does not prove the address, since some Google accounts carry an
    /// unverified email (linking keys on that claim, not on the
    /// mere fact of a successful Google sign-in). Null = unverified, the
    /// state the claim rules key on.
    /// </summary>
    public DateTimeOffset? EmailVerifiedAt { get; set; }

    /// <summary>
    /// The `ver` claim source: bumped on password change /
    /// sign-out-everywhere; enforced at refresh only.
    /// </summary>
    public required int TokenVersion { get; set; }

    /// <summary>
    /// The 7-day soft deadline, set at registration. After it,
    /// an unverified account's writes lock. Kept even
    /// after verification: verified-ness dominates, so clearing it would
    /// only destroy audit signal.
    /// </summary>
    public DateTimeOffset? VerificationDeadlineAt { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>users.status values in play this story (the schema owns the full set).</summary>
internal static class UserStatus
{
    public const string Active = "active";
}
