using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// Resolves the caller's EFFECTIVE permission set in the ACTIVE tenant, at tenant
/// scope or at one workspace (multi-tenancy.md section 13). Like
/// <see cref="TenantRoleResolver"/> this is a request-path RLS read, NOT the
/// bypass path: it opens an explicit read transaction so the tenant interceptor
/// sets the current-tenant GUC, so every row it reads is visible only under its
/// own tenant's GUC. It must therefore stay OUT of the bypass allowlist.
/// <para>
/// The tenant-scope set is the union of (1) the permission set of the caller's
/// ACTIVE membership's system role (owner | admin | member, from code, applied
/// tenant-wide) and (2) every TENANT-scope custom-role grant the caller holds -
/// either directly (principal_type = user) OR through a TEAM the caller belongs
/// to (principal_type = team; multi-tenancy.md section 14) - joined to that role's
/// permissions. The workspace-scope set is that same set PLUS (3) every
/// WORKSPACE-scope grant (user- or team-held) whose scope_id equals the requested
/// workspace. Inheritance is downward only, and it is enforced structurally: the
/// tenant-scope query never reads workspace-scope grants, so a workspace grant
/// can never confer anything tenant-wide; a workspace-scope grant is admitted
/// only when its scope_id matches exactly, so it never reaches another workspace.
/// </para>
/// <para>
/// It is fail-closed: no active membership resolves to the empty set (so a
/// suspended membership confers nothing, and a suspension takes effect on the
/// next request), and an unresolved tenant fails closed to zero rows. The caller's
/// team ids are read ONLY after the active-membership gate passes, so a suspended
/// member's team grants are never even reached; adding or removing a team member
/// takes effect on their next request (the read is per request, no token churn).
/// Resolution is cached per request keyed on (caller, scope) - the resolver is
/// scoped, and a request resolves at most its tenant set plus one workspace set.
/// </para>
/// </summary>
internal sealed class PermissionResolver(TenancyDbContext db) : IPermissionResolver
{
    // Cache key: (caller, workspace). A null workspace is the tenant-scope set; a
    // non-null workspace is that workspace's set. One request touches at most two
    // keys (tenant plus one workspace), so a small dictionary is right-sized.
    private readonly Dictionary<(Guid UserId, Guid? WorkspaceId), IReadOnlySet<string>> _cache = new();

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid userId, CancellationToken cancellationToken) =>
        GetAsync(userId, workspaceId: null, cancellationToken);

    public Task<IReadOnlySet<string>> GetCallerPermissionsAsync(
        Guid userId, Guid workspaceId, CancellationToken cancellationToken) =>
        GetAsync(userId, workspaceId, cancellationToken);

    private async Task<IReadOnlySet<string>> GetAsync(
        Guid userId, Guid? workspaceId, CancellationToken cancellationToken)
    {
        if (_cache.TryGetValue((userId, workspaceId), out var cached))
        {
            return cached;
        }

        var permissions = await ResolveAsync(userId, workspaceId, cancellationToken);
        _cache[(userId, workspaceId)] = permissions;
        return permissions;
    }

    private async Task<IReadOnlySet<string>> ResolveAsync(
        Guid userId, Guid? workspaceId, CancellationToken cancellationToken)
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
            // suspended member's custom-role AND team grants are never even read.
            await transaction.CommitAsync(cancellationToken);
            return EmptySet;
        }

        var permissions = new HashSet<string>(StringComparer.Ordinal);

        // (1) The system-role permission set, applied tenant-wide (so it inherits
        // into every workspace).
        if (MembershipRoles.ToTenantRole(role) is { } tenantRole)
        {
            foreach (var permission in SystemRolePermissions.For(tenantRole))
            {
                permissions.Add(permission);
            }
        }

        // The ids of the teams the caller belongs to (RLS-scoped, so only teams in
        // the active tenant). Read ONLY here, AFTER the active-membership gate
        // above, so a suspended member's team grants are never reached. A grant is
        // the caller's when its principal is the caller (user) OR one of these
        // teams. The empty-list case translates to "no team grant" with no special
        // casing (EF renders the team predicate as a false constant).
        var teamIds = await db.TeamMembers
            .AsNoTracking()
            .Where(member => member.UserId == userId)
            .Select(member => member.TeamId)
            .ToListAsync(cancellationToken);

        // (2) The caller's TENANT-scope grants - held directly (user) OR through a
        // team - unioned with the permissions of each granted role. These apply
        // tenant-wide, so they are included at tenant scope AND at every workspace
        // (downward inheritance).
        var tenantGrants = await (
            from assignment in db.RoleAssignments.AsNoTracking()
            where assignment.ScopeType == AssignmentScope.Tenant
                && ((assignment.PrincipalType == PrincipalType.User && assignment.PrincipalId == userId)
                    || (assignment.PrincipalType == PrincipalType.Team && teamIds.Contains(assignment.PrincipalId)))
            join permission in db.RolePermissions.AsNoTracking()
                on assignment.RoleId equals permission.RoleId
            select permission.Permission)
            .ToListAsync(cancellationToken);

        foreach (var permission in tenantGrants)
        {
            permissions.Add(permission);
        }

        // (3) WORKSPACE-scope grants (user- or team-held), admitted ONLY for the
        // requested workspace (scope_id == workspaceId). This is the sole place a
        // workspace grant enters the set, and it never enters the tenant-scope set
        // above, so a workspace grant confers nothing tenant-wide and nothing in
        // any other workspace (no upward inheritance).
        if (workspaceId is Guid scope)
        {
            var workspaceGrants = await (
                from assignment in db.RoleAssignments.AsNoTracking()
                where assignment.ScopeType == AssignmentScope.Workspace
                    && assignment.ScopeId == scope
                    && ((assignment.PrincipalType == PrincipalType.User && assignment.PrincipalId == userId)
                        || (assignment.PrincipalType == PrincipalType.Team && teamIds.Contains(assignment.PrincipalId)))
                join permission in db.RolePermissions.AsNoTracking()
                    on assignment.RoleId equals permission.RoleId
                select permission.Permission)
                .ToListAsync(cancellationToken);

            foreach (var permission in workspaceGrants)
            {
                permissions.Add(permission);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return permissions;
    }

    private static readonly IReadOnlySet<string> EmptySet =
        new HashSet<string>(StringComparer.Ordinal);
}
