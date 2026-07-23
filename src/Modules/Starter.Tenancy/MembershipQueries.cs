using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;

namespace Starter.Tenancy;

/// <summary>
/// Membership queries shared by more than one control-plane slice, kept in one place
/// so the rule they encode cannot drift between callers. Every query here runs on the
/// caller's request-path, RLS-bound <see cref="TenancyDbContext"/>, so it sees only
/// the active tenant's memberships.
/// </summary>
internal static class MembershipQueries
{
    /// <summary>
    /// True when the active tenant has at most one active owner: the last-owner guard
    /// shared by the tenant-admin member ops (multi-tenancy.md section 8) and the SCIM
    /// deactivate path (sso-and-scim.md section 5), so neither can strand a tenant with
    /// no owner. Only "is there more than one owner" matters, so the count is capped at
    /// two.
    /// </summary>
    public static async Task<bool> IsLastOwnerAsync(TenancyDbContext db, CancellationToken cancellationToken)
    {
        var owners = await db.Memberships
            .AsNoTracking()
            .Where(membership =>
                membership.Role == MembershipRole.Owner && membership.Status == MembershipStatus.Active)
            .Take(2)
            .CountAsync(cancellationToken);
        return owners <= 1;
    }
}
