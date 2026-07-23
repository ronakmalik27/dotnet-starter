namespace Starter.Platform.Auth;

/// <summary>
/// The install-wide platform policy floor (role-templates-and-policy-defaults.md
/// section 3): the operator-set password, session, and lockout defaults the whole
/// install inherits. It is a single operator-owned record on the no-RLS
/// <c>platform.policy_defaults</c> singleton table, so this reader is declared in
/// the platform (like <see cref="IEntitlementSource"/> and the port interfaces the
/// Tenancy module implements) and the consumers - the login hot path, the password
/// policy, and the access-token mint - depend on it without touching the Data-layer
/// row type.
/// <para>
/// Read on the login hot path, so the implementation keeps a SHORT in-process TTL
/// cache: per-request caching does not help across concurrent brute-force traffic,
/// so the cache must be shared across requests. It FAILS CLOSED to the built-in
/// constant defaults (<see cref="PolicyDefaults.BuiltIn"/>) if the singleton row is
/// somehow absent, and never throws on the auth path (the same explicit-fallback
/// discipline the tenant provisioner uses for its default-plan read).
/// </para>
/// </summary>
public interface IPolicyDefaults
{
    /// <summary>
    /// The current platform policy defaults, served from the short TTL cache when
    /// fresh and read from the no-RLS singleton otherwise. Falls back to the
    /// built-in constants when the row is absent; never throws.
    /// </summary>
    Task<PolicyDefaults> GetAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Drops the cached value so the next <see cref="GetAsync"/> re-reads the
    /// singleton. The super-admin update path calls this after committing a change,
    /// so a policy edit takes effect on the very next read in-process rather than
    /// waiting out the TTL.
    /// </summary>
    void Invalidate();
}

/// <summary>
/// The resolved platform policy defaults (role-templates-and-policy-defaults.md
/// section 3), by value. Every field is a positive integer; the built-in constants
/// (<see cref="BuiltIn"/>) are exactly the values the migration seeds, so a fresh
/// install and a fail-closed fallback behave identically to the pre-feature
/// constants.
/// </summary>
/// <param name="PasswordMinLength">Minimum password length, enforced at register / set / change.</param>
/// <param name="AccessTokenLifetimeSeconds">Access-token lifetime in seconds, enforced at access-token issue.</param>
/// <param name="RefreshLifetimeSeconds">Refresh-family lifetime in seconds, enforced at refresh-family issue.</param>
/// <param name="LockoutMaxAttempts">Failed-login attempts before the password credential locks.</param>
/// <param name="LockoutDurationSeconds">How long the credential stays locked, in seconds.</param>
public sealed record PolicyDefaults(
    int PasswordMinLength,
    int AccessTokenLifetimeSeconds,
    int RefreshLifetimeSeconds,
    int LockoutMaxAttempts,
    int LockoutDurationSeconds)
{
    /// <summary>
    /// The built-in constants the migration seeds and the reader fails closed to:
    /// min length 10, 15-minute access token, 30-day refresh family, 10 attempts,
    /// 15-minute lock. These ARE today's hard-coded constants, so nothing changes
    /// behavior on ship.
    /// </summary>
    public static readonly PolicyDefaults BuiltIn = new(
        PasswordMinLength: 10,
        AccessTokenLifetimeSeconds: 900,
        RefreshLifetimeSeconds: 2592000,
        LockoutMaxAttempts: 10,
        LockoutDurationSeconds: 900);
}
