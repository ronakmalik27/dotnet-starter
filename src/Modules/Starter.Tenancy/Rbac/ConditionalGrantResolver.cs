using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Auth.Conditions;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// Tier 2 of the ABAC seam (abac.md section 5): resolves whether the caller holds
/// a CONDITIONAL grant (a <c>role_assignments</c> row with a non-null
/// <c>condition</c>) that confers a permission at a scope AND whose condition is
/// satisfied by the current request's attributes. Like <see cref="PermissionResolver"/>
/// it is a request-path RLS read (it opens a read transaction so the tenant
/// interceptor sets the current-tenant GUC), NOT the bypass path, so it stays OUT
/// of the bypass allowlist.
/// <para>
/// The union logic is the SAME as <see cref="PermissionResolver"/>: for a user, the
/// active-membership gate (fail-closed) then direct plus team grants; for a service
/// account, grants-only with no membership gate; tenant scope plus, when asked, the
/// one workspace's scope (downward inheritance). The only difference is the filter
/// (<c>condition IS NOT NULL</c>) and that each matching grant's condition is
/// evaluated LIVE through the <see cref="ConditionEvaluatorRegistry"/> against the
/// passed attributes.
/// </para>
/// <para>
/// It MAY cache the loaded grant ROWS per request (they do not change within a
/// request), keyed by scope exactly as <see cref="PermissionResolver"/>'s
/// dictionary is, so a tenant-scope load never serves a workspace-scope query. It
/// MUST NOT cache the DECISION: the condition is re-evaluated against the passed
/// attributes on every call. Loading is lazy, so a caller with no conditional
/// grants (every tenant that has not adopted ABAC) gets an empty load and every
/// check short-circuits to false - the feature costs nothing until a conditional
/// grant exists. Fail-closed everywhere (abac.md section 7).
/// </para>
/// </summary>
internal sealed class ConditionalGrantResolver(TenancyDbContext db, ConditionEvaluatorRegistry registry)
    : IConditionalGrantResolver
{
    // Cache the LOADED ROWS per scope, keyed identically to PermissionResolver's
    // dictionary: (principal, workspace, principalType). The decision is never
    // cached - only the rows, which are stable within a request.
    private readonly Dictionary<(Guid PrincipalId, Guid? WorkspaceId, string PrincipalType), IReadOnlyList<ConditionalGrant>> _cache = new();

    public async Task<bool> IsGrantedAsync(
        Guid principalId,
        string principalType,
        string permission,
        RequestAttributes attributes,
        Guid? workspaceId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        ArgumentNullException.ThrowIfNull(attributes);

        var grants = await LoadAsync(principalId, principalType, workspaceId, cancellationToken);

        // Re-evaluate every matching grant's condition against THIS request's
        // attributes. At least one satisfied condition confers the permission;
        // anything else (no matching grant, all conditions false, any evaluation
        // error inside the registry) is fail-closed to false.
        foreach (var grant in grants)
        {
            if (string.Equals(grant.Permission, permission, StringComparison.Ordinal)
                && registry.IsSatisfied(grant.Condition, attributes))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<IReadOnlyList<ConditionalGrant>> LoadAsync(
        Guid principalId, string principalType, Guid? workspaceId, CancellationToken cancellationToken)
    {
        if (_cache.TryGetValue((principalId, workspaceId, principalType), out var cached))
        {
            return cached;
        }

        var grants = principalType == PrincipalTypes.ServiceAccount
            ? await LoadServiceAccountAsync(principalId, workspaceId, cancellationToken)
            : await LoadUserAsync(principalId, workspaceId, cancellationToken);
        _cache[(principalId, workspaceId, principalType)] = grants;
        return grants;
    }

    // A service account has NO membership and NO system role, and no team union
    // (service-accounts.md section 4): its conditional grants are exactly its own
    // service-account grants at tenant scope and (for a workspace request) the
    // requested workspace scope. Runs on the RLS request path (tid was bound from
    // the key), so the grants are read under the account's own tenant's boundary.
    private async Task<IReadOnlyList<ConditionalGrant>> LoadServiceAccountAsync(
        Guid serviceAccountId, Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var grants = new List<ConditionalGrant>();

        var tenantGrants = await (
            from assignment in db.RoleAssignments.AsNoTracking()
            where assignment.ScopeType == AssignmentScope.Tenant
                && assignment.PrincipalType == PrincipalType.ServiceAccount
                && assignment.PrincipalId == serviceAccountId
                && assignment.Condition != null
            join permission in db.RolePermissions.AsNoTracking()
                on assignment.RoleId equals permission.RoleId
            select new { permission.Permission, assignment.Condition })
            .ToListAsync(cancellationToken);
        grants.AddRange(tenantGrants.Select(row => new ConditionalGrant(row.Permission, row.Condition!)));

        if (workspaceId is Guid scope)
        {
            var workspaceGrants = await (
                from assignment in db.RoleAssignments.AsNoTracking()
                where assignment.ScopeType == AssignmentScope.Workspace
                    && assignment.ScopeId == scope
                    && assignment.PrincipalType == PrincipalType.ServiceAccount
                    && assignment.PrincipalId == serviceAccountId
                    && assignment.Condition != null
                join permission in db.RolePermissions.AsNoTracking()
                    on assignment.RoleId equals permission.RoleId
                select new { permission.Permission, assignment.Condition })
                .ToListAsync(cancellationToken);
            grants.AddRange(workspaceGrants.Select(row => new ConditionalGrant(row.Permission, row.Condition!)));
        }

        await transaction.CommitAsync(cancellationToken);
        return grants;
    }

    private async Task<IReadOnlyList<ConditionalGrant>> LoadUserAsync(
        Guid userId, Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The SAME active-membership gate as PermissionResolver: no active
        // membership resolves to no conditional grants, so a suspended member
        // reaches none. Team ids are read only AFTER this gate passes.
        var isActiveMember = await db.Memberships
            .AsNoTracking()
            .AnyAsync(
                membership => membership.UserId == userId && membership.Status == MembershipStatus.Active,
                cancellationToken);
        if (!isActiveMember)
        {
            await transaction.CommitAsync(cancellationToken);
            return Empty;
        }

        var teamIds = await db.TeamMembers
            .AsNoTracking()
            .Where(member => member.UserId == userId)
            .Select(member => member.TeamId)
            .ToListAsync(cancellationToken);

        var grants = new List<ConditionalGrant>();

        var tenantGrants = await (
            from assignment in db.RoleAssignments.AsNoTracking()
            where assignment.ScopeType == AssignmentScope.Tenant
                && ((assignment.PrincipalType == PrincipalType.User && assignment.PrincipalId == userId)
                    || (assignment.PrincipalType == PrincipalType.Team && teamIds.Contains(assignment.PrincipalId)))
                && assignment.Condition != null
            join permission in db.RolePermissions.AsNoTracking()
                on assignment.RoleId equals permission.RoleId
            select new { permission.Permission, assignment.Condition })
            .ToListAsync(cancellationToken);
        grants.AddRange(tenantGrants.Select(row => new ConditionalGrant(row.Permission, row.Condition!)));

        if (workspaceId is Guid scope)
        {
            var workspaceGrants = await (
                from assignment in db.RoleAssignments.AsNoTracking()
                where assignment.ScopeType == AssignmentScope.Workspace
                    && assignment.ScopeId == scope
                    && ((assignment.PrincipalType == PrincipalType.User && assignment.PrincipalId == userId)
                        || (assignment.PrincipalType == PrincipalType.Team && teamIds.Contains(assignment.PrincipalId)))
                    && assignment.Condition != null
                join permission in db.RolePermissions.AsNoTracking()
                    on assignment.RoleId equals permission.RoleId
                select new { permission.Permission, assignment.Condition })
                .ToListAsync(cancellationToken);
            grants.AddRange(workspaceGrants.Select(row => new ConditionalGrant(row.Permission, row.Condition!)));
        }

        await transaction.CommitAsync(cancellationToken);
        return grants;
    }

    private static readonly IReadOnlyList<ConditionalGrant> Empty = [];

    // A loaded conditional grant row: the permission it confers and the raw
    // condition JSON to evaluate. Condition is non-null by the query filter.
    private sealed record ConditionalGrant(string Permission, string Condition);
}
