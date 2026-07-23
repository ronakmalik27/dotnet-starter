namespace Starter.Platform.Data;

/// <summary>
/// The single <c>platform.policy_defaults</c> row: the install-wide password,
/// session, and lockout defaults (role-templates-and-policy-defaults.md section 3).
/// A no-RLS operator-owned record like the plan and feature-flag catalogues, but the
/// FIRST SINGLETON shape here: the primary key is a <see cref="OneRow"/> boolean
/// fixed to <c>true</c> with a <c>check (one_row)</c>, so exactly one row can ever
/// exist. That is intentional - a true install-wide record has no "which is active"
/// and no demote-race, so the singleton is simpler than the multi-row + is_default
/// pattern the other catalogues use.
/// <para>
/// The migration SEEDS the one row with today's constant values
/// (<see cref="Starter.Platform.Auth.PolicyDefaults.BuiltIn"/>), so nothing changes
/// on ship. Super-admin reads and updates it on the bypass path; the request role is
/// REVOKE'd write on it (the operator-catalogue grant pattern), and reads it no-RLS
/// on the login hot path through <see cref="Starter.Platform.Auth.IPolicyDefaults"/>.
/// </para>
/// </summary>
internal sealed class PolicyDefaultsRow
{
    /// <summary>Primary key, fixed true with a check constraint: the singleton guarantee.</summary>
    public bool OneRow { get; init; } = true;

    /// <summary>Minimum password length, enforced at register / set / change.</summary>
    public required int PasswordMinLength { get; init; }

    /// <summary>Access-token lifetime in seconds, enforced at access-token issue.</summary>
    public required int AccessTokenLifetimeSeconds { get; init; }

    /// <summary>Refresh-family lifetime in seconds, enforced at refresh-family issue.</summary>
    public required int RefreshLifetimeSeconds { get; init; }

    /// <summary>Failed-login attempts before the password credential locks.</summary>
    public required int LockoutMaxAttempts { get; init; }

    /// <summary>How long the credential stays locked, in seconds.</summary>
    public required int LockoutDurationSeconds { get; init; }
}
