namespace Starter.Platform.Auth;

/// <summary>
/// A caller's capability role in the active tenant (multi-tenancy.md section 5,
/// layer 2). Ranked by the underlying value so a minimum-role check is a plain
/// comparison: owner (3) outranks admin (2) outranks member (1). The token
/// carries no role - it is resolved per request from the membership table, the
/// same "authorize against the data" stance the starter takes for ownership - so
/// this is the platform-level shape that lookup returns, keeping the Tenancy
/// module's storage strings (owner | admin | member) off the shared surface.
/// </summary>
public enum TenantRole
{
    /// <summary>A member manages only the resources they own within the tenant.</summary>
    Member = 1,

    /// <summary>An admin manages members, invitations, settings, and any resource in the tenant.</summary>
    Admin = 2,

    /// <summary>The single owner: admin capabilities plus ownership transfer and tenant delete.</summary>
    Owner = 3,
}
