namespace Starter.Platform.Auth;

/// <summary>
/// The outcome of staging a registration on a caller-owned transaction (the
/// Identity staging seam used by self-serve tenant provisioning). Either a
/// brand-new account was staged - carrying its id and the raw verification
/// token, held only in memory for the post-commit email - or the email already
/// belongs to an account, in which case NOTHING was staged and the caller rolls
/// the whole unit back. It lives in the platform, not the Identity module,
/// because a module exports no types beyond its Api interface and bootstrap
/// class, and the tenancy provisioner (a separate module) consumes this across
/// the boundary.
/// </summary>
public sealed record StagedRegistration
{
    private StagedRegistration(bool emailAlreadyExists, Guid userId, string? rawVerificationToken)
    {
        EmailAlreadyExists = emailAlreadyExists;
        UserId = userId;
        RawVerificationToken = rawVerificationToken;
    }

    /// <summary>
    /// True when the email already had an account, so the seam staged nothing.
    /// The caller returns the same generic success as a fresh signup and does
    /// not leak that the address pre-existed (no-account-enumeration).
    /// </summary>
    public bool EmailAlreadyExists { get; }

    /// <summary>The new account's id; <see cref="Guid.Empty"/> when the email already existed.</summary>
    public Guid UserId { get; }

    /// <summary>
    /// The raw verify-email token for the freshly-staged account, or null when
    /// the email already existed. It exists only in memory here (never persisted
    /// raw, never on the event spine) and reaches the owner solely through the
    /// post-commit verification email.
    /// </summary>
    public string? RawVerificationToken { get; }

    /// <summary>The email already belongs to an account; nothing was staged.</summary>
    public static readonly StagedRegistration AlreadyExists = new(true, Guid.Empty, null);

    /// <summary>A new account was staged on the shared transaction.</summary>
    public static StagedRegistration Created(Guid userId, string rawVerificationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawVerificationToken);
        return new StagedRegistration(false, userId, rawVerificationToken);
    }
}
