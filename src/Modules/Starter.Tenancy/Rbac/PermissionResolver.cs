using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// Resolves the caller's EFFECTIVE permission set in the ACTIVE tenant at tenant
/// scope (multi-tenancy.md section 13). Like <see cref="TenantRoleResolver"/>
/// this is a request-path RLS read, NOT the bypass path: it opens an explicit
/// read transaction so the tenant interceptor sets the current-tenant GUC, so
/// every row it reads is visible only under its own tenant's GUC. It must
/// therefore stay OUT of the bypass allowlist.
/// <para>
/// The effective set is the union of (1) the permission set of the caller's
/// ACTIVE membership's system role (owner | admin | member, from code, applied
/// tenant-wide) and (2) every tenant-scope custom-role grant the caller holds,
/// joined to that role's permissions. It is fail-closed: no active membership
/// resolves to the empty set (so a suspended membership confers nothing, and a
/// suspension takes effect on the next request), and an unresolved tenant fails
/// closed to zero rows. Resolution is cached per request - the resolver is
/// scoped, and the caller id is constant across a request's gate invocations.
/// </para>
/// </summary>
internal sealed class PermissionResolver(TenancyDbContext db) : IPermissionResolver
{
    private (Guid UserId, IReadOnlySet<string> Permissions)? _cache;

    public async Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid userId, CancellationToken cancellationToken)
    {
        if (_cache is { } cached && cached.UserId == userId)
        {
            return cached.Permissions;
        }

        var permissions = await ResolveAsync(userId, cancellationToken);
        _cache = (userId, permissions);
        return permissions;
    }

    private async Task<IReadOnlySet<string>> ResolveAsync(Guid userId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The caller's ACTIVE membership role. RLS + the EF filter scope to the
        // active tenant, and (tenant_id, user_id) is unique, so this is one row.
        var role = await db.Memberships
            .AsNoTracking()
            .Where(membership => membership.UserId == userId && membership.Status == MembershipStatus.Active)
            .Select(membership => membership.Role)
            .SingleOrDefaultAsync(cancellationToken);

        if (role is null)
        {
            // Fail closed: no active membership means no permissions at all, so a
            // suspended member's custom-role grants are never even read.
            await transaction.CommitAsync(cancellationToken);
            return EmptySet;
        }

        var permissions = new HashSet<string>(StringComparer.Ordinal);

        // (1) The system-role permission set, applied tenant-wide.
        if (MembershipRoles.ToTenantRole(role) is { } tenantRole)
        {
            foreach (var permission in SystemRolePermissions.For(tenantRole))
            {
                permissions.Add(permission);
            }
        }

        // (2) The caller's tenant-scope custom-role grants, unioned with the
        // permissions of each granted role. principal_type = user this increment.
        var granted = await (
            from assignment in db.RoleAssignments.AsNoTracking()
            where assignment.PrincipalType == PrincipalType.User
                && assignment.PrincipalId == userId
                && assignment.ScopeType == AssignmentScope.Tenant
            join permission in db.RolePermissions.AsNoTracking()
                on assignment.RoleId equals permission.RoleId
            select permission.Permission)
            .ToListAsync(cancellationToken);

        foreach (var permission in granted)
        {
            permissions.Add(permission);
        }

        await transaction.CommitAsync(cancellationToken);
        return permissions;
    }

    private static readonly IReadOnlySet<string> EmptySet =
        new HashSet<string>(StringComparer.Ordinal);
}
