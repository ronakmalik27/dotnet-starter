using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// Resolves the caller's role in the ACTIVE tenant (multi-tenancy.md section 5,
/// layer 2). This is a request-path RLS read, NOT the bypass path: it opens an
/// explicit read transaction so the tenant interceptor sets the current-tenant
/// GUC, exactly as increment 1's note reads do, so a membership row is visible
/// only under its own tenant's GUC. It must therefore stay OUT of the bypass
/// allowlist.
/// <para>
/// It backs both entry points to the same lookup with no drift: the platform's
/// <see cref="ITenantRoleReader"/> seam (used by the layer-3 resource handler)
/// and <c>ITenancyApi.GetCallerRoleAsync</c> (used by the RequireTenantRole
/// endpoint gate), which the module facade delegates here. A caller with no
/// active membership in the active tenant - including an unresolved tenant,
/// which fails closed to zero rows - resolves to null.
/// </para>
/// </summary>
internal sealed class TenantRoleResolver(TenancyDbContext db) : ITenantRoleReader
{
    public async Task<TenantRole?> GetCallerRoleAsync(Guid userId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // RLS + the EF query filter both scope to the active tenant, and
        // (tenant_id, user_id) is unique, so this is a single indexed row.
        var role = await db.Memberships
            .AsNoTracking()
            .Where(membership => membership.UserId == userId && membership.Status == MembershipStatus.Active)
            .Select(membership => membership.Role)
            .SingleOrDefaultAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return role is null ? null : MembershipRoles.ToTenantRole(role);
    }
}
