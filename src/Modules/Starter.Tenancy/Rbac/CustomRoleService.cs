using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Auth.Conditions;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// The custom-role and assignment control plane (multi-tenancy.md sections 13,
/// 15), all operating on the ACTIVE tenant on the REQUEST path under row-level
/// security - NOT the bypass path. Every write opens a transaction so the tenant
/// interceptor sets the current-tenant GUC (RLS then binds every read and write
/// to the active tenant), stamps its domain event through the OutboxWriter, and
/// commits once. The endpoint's RequirePermission(roles:manage) gate runs before
/// this; the business rules here are the catalogue and scope guardrails RLS does
/// not express: catalogue-subset, owner-reserved refusal, key uniqueness,
/// assignable-scope validation, active-member validation, and delete-in-use.
/// </summary>
internal sealed class CustomRoleService(
    TenancyDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    IEntitlementSource entitlements,
    ConditionEvaluatorRegistry conditions,
    Clock clock)
{
    // --- Roles ------------------------------------------------------------

    public async Task<Result<Guid>> CreateRoleAsync(
        Guid callerUserId,
        string key,
        string name,
        string? description,
        string assignableAt,
        Guid? workspaceId,
        IReadOnlyCollection<string> permissions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(assignableAt);
        ArgumentNullException.ThrowIfNull(permissions);

        key = key.Trim();
        name = name.Trim();
        description = description?.Trim();

        if (key.Length == 0 || key.Length > 64)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.role_key_invalid", "A role key must be 1-64 characters."));
        }

        if (name.Length == 0)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.role_name_required", "A role name is required."));
        }

        if (!RoleAssignableAt.IsValid(assignableAt))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.role_assignable_at_invalid", "assignableAt must be tenant, workspace, or both."));
        }

        // A workspace-local role (workspace_id set) is defined by a workspace
        // admin and is assignable ONLY in its own workspace (section 15), so its
        // only sensible assignable scope is 'workspace'. Refuse a mismatch rather
        // than silently coercing it.
        if (workspaceId is not null && assignableAt != RoleAssignableAt.Workspace)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.workspace_role_assignable",
                "A workspace-local role must be assignable at workspace scope only."));
        }

        var distinctPermissions = Distinct(permissions);
        if (ValidatePermissions(distinctPermissions) is { } permissionError)
        {
            return Result.Failure<Guid>(permissionError);
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // A workspace-local role must name a workspace that exists in this tenant
        // (RLS-scoped read). The endpoint's RequireWorkspace gate already checked
        // this; the service re-checks so the business rule holds for any caller.
        if (workspaceId is Guid ws)
        {
            var workspaceExists = await db.Workspaces
                .AsNoTracking()
                .AnyAsync(workspace => workspace.Id == ws, cancellationToken);
            if (!workspaceExists)
            {
                return Result.Failure<Guid>(WorkspaceNotFound);
            }
        }

        // A key is unique within its owning scope: (tenant, workspace_id, key).
        // The pre-check keys on the same workspace_id as the new row (null for a
        // tenant-owned role); the unique index is the race backstop.
        var duplicate = await db.Roles
            .AsNoTracking()
            .AnyAsync(role => role.WorkspaceId == workspaceId && role.Key == key, cancellationToken);
        if (duplicate)
        {
            return Result.Failure<Guid>(RoleKeyTaken);
        }

        // The plan permission-catalogue gate, the role + role_permissions insert,
        // and the RoleCreated event run through the transaction-agnostic helper on
        // this open transaction. The endpoint path REJECTS a permission the plan
        // omits (skipDisallowedByPlan: false); a tenant-authored role carries no
        // template (templateKey: null).
        var result = await InsertRoleOnOpenTransactionAsync(
            db,
            tenant.TenantId,
            callerUserId,
            key,
            name,
            description,
            assignableAt,
            workspaceId,
            templateKey: null,
            distinctPermissions,
            skipDisallowedByPlan: false,
            now,
            cancellationToken);
        if (result.IsFailure)
        {
            // Dispose (below) rolls back; nothing was committed.
            return result;
        }

        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    /// <summary>
    /// The role + role_permissions insert plus the RoleCreated event, run inside an
    /// ALREADY-OPEN transaction on the supplied context (so the tenant interceptor's
    /// RLS GUC is set): it applies the plan permission-catalogue gate
    /// (billing-and-entitlements.md section 4a), inserts the role row and its
    /// permissions, and enqueues the granted event, but never opens or commits a
    /// transaction - the caller owns that. TRANSACTION-AGNOSTIC by design
    /// (role-templates-and-policy-defaults.md section 2): the endpoint-facing
    /// <see cref="CreateRoleAsync"/> wraps it in its own transaction on the
    /// request-scoped context, while the provisioner's seeding path and the
    /// super-admin bulk-seed call it directly on their own open bypass transaction,
    /// so <c>CreateRoleAsync</c> is never re-entered (it would begin a second
    /// transaction and throw). Because both seeding callers operate on a bypass
    /// connection, the context is passed in rather than the injected one; the plan
    /// read binds to the context's own tenant filter.
    /// <para>
    /// <paramref name="skipDisallowedByPlan"/> selects the two plan behaviors: the
    /// endpoint path passes <c>false</c> and REJECTS a permission the plan does not
    /// grant (<c>tenancy.permission_not_in_plan</c>); the seeding path passes
    /// <c>true</c> and SKIPS a disallowed permission (the seeded role gets the
    /// plan-allowed subset, never a permission-escalation past the plan). An empty
    /// resulting set still creates the role.
    /// </para>
    /// </summary>
    internal async Task<Result<Guid>> InsertRoleOnOpenTransactionAsync(
        TenancyDbContext context,
        Guid tenantId,
        Guid callerUserId,
        string key,
        string name,
        string? description,
        string assignableAt,
        Guid? workspaceId,
        string? templateKey,
        IReadOnlyCollection<string> distinctPermissions,
        bool skipDisallowedByPlan,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Resolve the tenant's plan and apply the catalogue gate. Fail-open: the
        // default NULL-permissions plan (or an unknown / null plan) allows every
        // non-owner-reserved permission, so an unrestricted plan seeds the full set
        // and existing custom-role authoring is unaffected. Skipped when the set is
        // empty (no plan read needed).
        var effective = new List<string>(distinctPermissions);
        if (effective.Count > 0)
        {
            var resolved = await ResolveTenantPlanAsync(context, cancellationToken);
            if (skipDisallowedByPlan)
            {
                effective = effective.Where(resolved.AllowsPermission).ToList();
            }
            else
            {
                foreach (var permission in effective)
                {
                    if (!resolved.AllowsPermission(permission))
                    {
                        return Result.Failure<Guid>(new Error(
                            ErrorKind.Validation,
                            "tenancy.permission_not_in_plan",
                            $"'{permission}' is not included in this tenant's plan."));
                    }
                }
            }
        }

        var roleRow = new CustomRole
        {
            Id = Ids.NewId(now),
            TenantId = tenantId,
            Key = key,
            Name = name,
            Description = description,
            AssignableAt = assignableAt,
            WorkspaceId = workspaceId,
            TemplateKey = templateKey,
            CreatedBy = callerUserId,
            CreatedAt = now,
        };
        context.Roles.Add(roleRow);
        foreach (var permission in effective)
        {
            context.RolePermissions.Add(new RolePermission
            {
                RoleId = roleRow.Id,
                TenantId = tenantId,
                Permission = permission,
            });
        }

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // The (tenant, workspace_id, key) index or the (tenant, template_key)
            // seeding backstop fired: to the endpoint caller a key clash, to the
            // seeding caller "already seeded" (it treats this as a benign skip).
            return Result.Failure<Guid>(RoleKeyTaken);
        }

        await outbox.EnqueueAsync(
            context, TenancyEvents.RoleCreated(roleRow.Id, key, callerUserId, now), cancellationToken);

        return Result.Success(roleRow.Id);
    }

    public Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListRolesAsync(CancellationToken cancellationToken) =>
        // The tenant roster is the tenant-OWNED roles (workspace_id null); a
        // workspace-local role is listed in its own workspace (section 15).
        ListRolesAsync(workspaceId: null, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListWorkspaceRolesAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        ListRolesAsync(workspaceId, cancellationToken);

    private async Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListRolesAsync(Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Roles
            .AsNoTracking()
            .Where(role => role.WorkspaceId == workspaceId)
            .OrderBy(role => role.CreatedAt)
            .ThenBy(role => role.Id)
            .Select(role => new
            {
                role.Id,
                role.Key,
                role.Name,
                role.Description,
                role.AssignableAt,
                role.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.Key, row.Name, row.Description, row.AssignableAt, row.CreatedAt))
            .ToList();
    }

    public async Task<Result<(Guid Id, string Key, string Name, string? Description, string AssignableAt, IReadOnlyList<string> Permissions, DateTimeOffset CreatedAt)>>
        GetRoleAsync(Guid roleId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var role = await db.Roles
            .AsNoTracking()
            .Where(candidate => candidate.Id == roleId)
            .Select(candidate => new
            {
                candidate.Id,
                candidate.Key,
                candidate.Name,
                candidate.Description,
                candidate.AssignableAt,
                candidate.CreatedAt,
            })
            .SingleOrDefaultAsync(cancellationToken);
        if (role is null)
        {
            return Result.Failure<(Guid, string, string, string?, string, IReadOnlyList<string>, DateTimeOffset)>(
                RoleNotFound);
        }

        var permissions = await db.RolePermissions
            .AsNoTracking()
            .Where(permission => permission.RoleId == roleId)
            .OrderBy(permission => permission.Permission)
            .Select(permission => permission.Permission)
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success<(Guid, string, string, string?, string, IReadOnlyList<string>, DateTimeOffset)>(
            (role.Id, role.Key, role.Name, role.Description, role.AssignableAt, permissions, role.CreatedAt));
    }

    public async Task<Result> UpdateRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string? name,
        string? description,
        IReadOnlyCollection<string>? permissions,
        CancellationToken cancellationToken)
    {
        name = name?.Trim();
        description = description?.Trim();

        if (name is { Length: 0 })
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.role_name_required", "A role name cannot be empty."));
        }

        var distinctPermissions = permissions is null ? null : Distinct(permissions);
        if (distinctPermissions is not null && ValidatePermissions(distinctPermissions) is { } permissionError)
        {
            return Result.Failure(permissionError);
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var role = await db.Roles.SingleOrDefaultAsync(
            candidate => candidate.Id == roleId, cancellationToken);
        if (role is null)
        {
            return Result.Failure(RoleNotFound);
        }

        // The plan permission-catalogue gate (section 4a): a replacement permission
        // set must sit within the tenant's plan. Only checked when the caller sends
        // a permission set; fail-open on the default NULL-permissions plan.
        if (distinctPermissions is not null
            && await ValidatePlanPermissionsAsync(distinctPermissions, cancellationToken) is { } planError)
        {
            return Result.Failure(planError);
        }

        if (name is not null)
        {
            role.Name = name;
        }

        // A null description leaves it unchanged; the caller clears it by sending
        // an empty string (normalized to null above only when it trims to empty).
        if (description is not null)
        {
            role.Description = description.Length == 0 ? null : description;
        }

        if (distinctPermissions is not null)
        {
            var existing = await db.RolePermissions
                .Where(permission => permission.RoleId == roleId)
                .ToListAsync(cancellationToken);

            // Diff so a permission carried across the edit is neither deleted nor
            // re-inserted (a delete+insert of the same PK in one SaveChanges is a
            // tracking conflict).
            foreach (var permission in existing.Where(p => !distinctPermissions.Contains(p.Permission)))
            {
                db.RolePermissions.Remove(permission);
            }

            var existingKeys = existing.Select(p => p.Permission).ToHashSet(StringComparer.Ordinal);
            foreach (var permission in distinctPermissions.Where(p => !existingKeys.Contains(p)))
            {
                db.RolePermissions.Add(new RolePermission
                {
                    RoleId = roleId,
                    TenantId = tenant.TenantId,
                    Permission = permission,
                });
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.RoleUpdated(roleId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> DeleteRoleAsync(
        Guid callerUserId, Guid roleId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var role = await db.Roles.SingleOrDefaultAsync(
            candidate => candidate.Id == roleId, cancellationToken);
        if (role is null)
        {
            return Result.Failure(RoleNotFound);
        }

        // A role in use cannot be deleted: its grants must be revoked or
        // reassigned first, so access never silently vanishes or dangles.
        var inUse = await db.RoleAssignments
            .AsNoTracking()
            .AnyAsync(assignment => assignment.RoleId == roleId, cancellationToken);
        if (inUse)
        {
            return Result.Failure(RoleInUse);
        }

        // The role's permissions cascade with it (the FK); the assignment FK is
        // Restrict, but the in-use check above guarantees none exist here.
        db.Roles.Remove(role);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.RoleDeleted(roleId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Assignments ------------------------------------------------------

    public async Task<Result<Guid>> AssignRoleAsync(
        Guid callerUserId,
        Guid roleId,
        string principalType,
        Guid principalId,
        string scopeType,
        Guid? scopeId,
        string? condition,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principalType);
        ArgumentNullException.ThrowIfNull(scopeType);

        if (principalType is not (PrincipalType.User or PrincipalType.Team or PrincipalType.ServiceAccount))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.principal_type_invalid",
                "principalType must be user, team, or service_account."));
        }

        if (scopeType is not (AssignmentScope.Tenant or AssignmentScope.Workspace))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.scope_invalid", "scopeType must be tenant or workspace."));
        }

        // A workspace-scope grant must name the workspace; a tenant-scope grant
        // must not (scope_id is null for tenant scope).
        if (scopeType == AssignmentScope.Workspace && scopeId is null)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.scope_id_required", "A workspace-scope grant requires a scopeId."));
        }

        var normalizedScopeId = scopeType == AssignmentScope.Workspace ? scopeId : null;

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var result = await AssignRoleCoreAsync(
            callerUserId, roleId, principalType, principalId, scopeType, normalizedScopeId, condition, now, cancellationToken);
        if (result.IsFailure)
        {
            // Dispose (below) rolls back; nothing was committed.
            return result;
        }

        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    /// <summary>
    /// The scope- and principal-validated grant, run inside an ALREADY-OPEN
    /// transaction on the shared context (so the tenant interceptor's RLS GUC is
    /// set): it validates and inserts the assignment and enqueues the granted
    /// event, but never opens or commits a transaction - the caller owns that.
    /// The tenant-scope assign path (<see cref="AssignRoleAsync"/>) wraps it; the
    /// service-account create-with-role path (<c>ServiceAccountService</c>) calls
    /// it in the SAME transaction as the account insert, so a self-escalation
    /// refusal rolls the whole create back (service-accounts.md section 4). The
    /// shape checks (principal type, scope kind, scope-id presence) are the
    /// caller's; this validates against tenant data. <paramref name="scopeId"/> is
    /// already normalized (null for tenant scope). <paramref name="condition"/> is
    /// the optional ABAC condition envelope (abac.md section 6): when non-null it is
    /// validated through the registry BEFORE the insert (a malformed payload is
    /// <c>tenancy.condition_invalid</c> and writes no row) and stored on the grant,
    /// and its parsed type rides the audit event.
    /// </summary>
    internal async Task<Result<Guid>> AssignRoleCoreAsync(
        Guid callerUserId,
        Guid roleId,
        string principalType,
        Guid principalId,
        string scopeType,
        Guid? scopeId,
        string? condition,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Validate the ABAC condition at grant time (abac.md section 6): an unknown
        // type or a malformed payload (a bad CIDR, a non-HH:mm time) is rejected
        // here rather than becoming a silent never-satisfied grant. The parsed type
        // rides the audit event; the raw condition is stored on the row. This runs
        // before any DB read or the insert, so a bad condition writes nothing.
        string? conditionType = null;
        if (condition is not null)
        {
            try
            {
                conditionType = conditions.Validate(condition);
            }
            catch (ConditionFormatException)
            {
                return Result.Failure<Guid>(ConditionInvalid);
            }
        }

        var role = await db.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, cancellationToken);
        if (role is null)
        {
            return Result.Failure<Guid>(RoleNotFound);
        }

        // A workspace-LOCAL role (workspace_id set) can ONLY be granted at its own
        // workspace (section 13): reject a tenant-scope grant and a grant at any
        // other workspace, so a role can never be bound wider than its author
        // intended. This is checked before the assignable-scope rule so the
        // message is specific to the scope-mismatch case.
        if (role.WorkspaceId is Guid roleWorkspace
            && (scopeType != AssignmentScope.Workspace || scopeId != roleWorkspace))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.workspace_role_scope",
                "A workspace-local role can only be assigned at its own workspace."));
        }

        // The scope must be one the role author allowed (its assignable_at).
        if (!RoleAssignableAt.Allows(role.AssignableAt, scopeType))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.scope_not_assignable",
                $"This role cannot be assigned at {scopeType} scope."));
        }

        // A service account cannot be granted the self-escalation primitives
        // (service-accounts.md section 4): a role whose permission set intersects
        // {roles:manage, api-keys:manage} is refused to a service-account
        // principal, so a leaked or over-scoped key cannot expand its OWN
        // authority. The same role assigns fine to a user or team. Read the role's
        // permissions and intersect in memory (a role carries few); the check runs
        // for BOTH the direct assign path and create-with-initial-role, since both
        // reach here.
        if (principalType == PrincipalType.ServiceAccount)
        {
            var permissions = await db.RolePermissions
                .AsNoTracking()
                .Where(permission => permission.RoleId == roleId)
                .Select(permission => permission.Permission)
                .ToListAsync(cancellationToken);
            if (permissions.Any(Permissions.IsNotServiceAccountGrantable))
            {
                return Result.Failure<Guid>(PermissionNotAutomatable);
            }
        }

        // A workspace-scope grant must name a workspace that exists in this tenant
        // (RLS-scoped read); the endpoint's RequireWorkspace gate already checked
        // it, but the service holds the rule for any caller.
        if (scopeType == AssignmentScope.Workspace)
        {
            var workspaceExists = await db.Workspaces
                .AsNoTracking()
                .AnyAsync(workspace => workspace.Id == scopeId, cancellationToken);
            if (!workspaceExists)
            {
                return Result.Failure<Guid>(WorkspaceNotFound);
            }
        }

        // The principal must exist in the active tenant (RLS-scoped read): a user
        // principal must be an ACTIVE member; a team principal must be a real team;
        // a service-account principal must be a real account that is neither
        // revoked nor past its expiry (a revoked/expired account can no more
        // receive a new grant than a suspended member). All reads are RLS-bound,
        // so a principal from another tenant is invisible and fails validation.
        switch (principalType)
        {
            case PrincipalType.User:
            {
                var isActiveMember = await db.Memberships
                    .AsNoTracking()
                    .AnyAsync(
                        membership => membership.UserId == principalId
                            && membership.Status == MembershipStatus.Active,
                        cancellationToken);
                if (!isActiveMember)
                {
                    return Result.Failure<Guid>(new Error(
                        ErrorKind.Validation,
                        "tenancy.principal_not_member",
                        "The target user is not an active member of this tenant."));
                }

                break;
            }

            case PrincipalType.Team:
            {
                var teamExists = await db.Teams
                    .AsNoTracking()
                    .AnyAsync(team => team.Id == principalId, cancellationToken);
                if (!teamExists)
                {
                    return Result.Failure<Guid>(new Error(
                        ErrorKind.Validation,
                        "tenancy.principal_team_not_found",
                        "The target team does not exist in this tenant."));
                }

                break;
            }

            default:
            {
                var accountValid = await db.ServiceAccounts
                    .AsNoTracking()
                    .AnyAsync(
                        account => account.Id == principalId
                            && account.RevokedAt == null
                            && (account.ExpiresAt == null || account.ExpiresAt > now),
                        cancellationToken);
                if (!accountValid)
                {
                    return Result.Failure<Guid>(new Error(
                        ErrorKind.Validation,
                        "tenancy.principal_not_service_account",
                        "The target service account does not exist, or is revoked or expired, in this tenant."));
                }

                break;
            }
        }

        var alreadyAssigned = await db.RoleAssignments
            .AsNoTracking()
            .AnyAsync(
                assignment => assignment.PrincipalType == principalType
                    && assignment.PrincipalId == principalId
                    && assignment.RoleId == roleId
                    && assignment.ScopeType == scopeType
                    && assignment.ScopeId == scopeId,
                cancellationToken);
        if (alreadyAssigned)
        {
            return Result.Failure<Guid>(AssignmentExists);
        }

        var assignmentRow = new RoleAssignment
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            PrincipalType = principalType,
            PrincipalId = principalId,
            RoleId = roleId,
            ScopeType = scopeType,
            ScopeId = scopeId,
            GrantedBy = callerUserId,
            CreatedAt = now,
            Condition = condition,
        };
        db.RoleAssignments.Add(assignmentRow);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(AssignmentExists);
        }

        await outbox.EnqueueAsync(
            db,
            TenancyEvents.RoleAssignmentGranted(
                assignmentRow.Id, roleId, principalId, callerUserId, conditionType, now),
            cancellationToken);

        return Result.Success(assignmentRow.Id);
    }

    public async Task<Result> RevokeAssignmentAsync(
        Guid callerUserId, Guid assignmentId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var assignment = await db.RoleAssignments.SingleOrDefaultAsync(
            candidate => candidate.Id == assignmentId, cancellationToken);
        if (assignment is null)
        {
            return Result.Failure(new Error(
                ErrorKind.NotFound, "tenancy.assignment_not_found", "No such role assignment."));
        }

        db.RoleAssignments.Remove(assignment);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db,
            TenancyEvents.RoleAssignmentRevoked(assignmentId, assignment.RoleId, assignment.PrincipalId, callerUserId, now),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, string? Condition, DateTimeOffset CreatedAt)>>
        ListAssignmentsAsync(CancellationToken cancellationToken) =>
        // The tenant roster lists every assignment (tenant- and workspace-scoped)
        // so an admin sees the full grant picture.
        ListAssignmentsAsync(workspaceId: null, cancellationToken);

    public Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, string? Condition, DateTimeOffset CreatedAt)>>
        ListWorkspaceAssignmentsAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        ListAssignmentsAsync(workspaceId, cancellationToken);

    private async Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, string? Condition, DateTimeOffset CreatedAt)>>
        ListAssignmentsAsync(Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var query = db.RoleAssignments.AsNoTracking();

        // A workspace listing is only that workspace's grants (scope_type =
        // workspace, scope_id = the workspace); a null filter is the full roster.
        if (workspaceId is Guid scope)
        {
            query = query.Where(
                assignment => assignment.ScopeType == AssignmentScope.Workspace && assignment.ScopeId == scope);
        }

        var rows = await query
            .OrderBy(assignment => assignment.CreatedAt)
            .ThenBy(assignment => assignment.Id)
            .Select(assignment => new
            {
                assignment.Id,
                assignment.RoleId,
                assignment.PrincipalType,
                assignment.PrincipalId,
                assignment.ScopeType,
                assignment.ScopeId,
                assignment.Condition,
                assignment.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (
                row.Id, row.RoleId, row.PrincipalType, row.PrincipalId, row.ScopeType, row.ScopeId, row.Condition, row.CreatedAt))
            .ToList();
    }

    // --- Helpers ----------------------------------------------------------

    private static readonly Error RoleNotFound = new(
        ErrorKind.NotFound, "tenancy.role_not_found", "No such custom role.");

    private static readonly Error WorkspaceNotFound = new(
        ErrorKind.NotFound, "tenancy.workspace_not_found", "No such workspace.");

    private static readonly Error RoleKeyTaken = new(
        ErrorKind.Conflict, "tenancy.role_key_taken", "A role with that key already exists.");

    private static readonly Error RoleInUse = new(
        ErrorKind.Conflict, "tenancy.role_in_use", "The role has assignments; revoke them before deleting it.");

    private static readonly Error AssignmentExists = new(
        ErrorKind.Conflict, "tenancy.assignment_exists", "That role is already assigned to the principal at this scope.");

    private static readonly Error ConditionInvalid = new(
        ErrorKind.Validation,
        "tenancy.condition_invalid",
        "The grant condition is malformed: an unknown type, or invalid type-specific fields.");

    private static readonly Error PermissionNotAutomatable = new(
        ErrorKind.Validation,
        "tenancy.permission_not_automatable",
        "This role cannot be assigned to a service account: it grants a self-escalation "
        + "permission (roles:manage or api-keys:manage) that an unattended credential must not hold.");

    private static List<string> Distinct(IReadOnlyCollection<string> permissions) =>
        permissions
            .Where(permission => !string.IsNullOrWhiteSpace(permission))
            .Select(permission => permission.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// The plan permission-catalogue gate (billing-and-entitlements.md section 4a):
    /// each requested permission must be <c>AllowsPermission</c> under the active
    /// tenant's plan, else the write is refused with an upgrade error
    /// (<c>tenancy.permission_not_in_plan</c>). Fail-open: the tenant's plan is
    /// resolved exactly as <c>GetCallerEntitlementsAsync</c> does (the plan key from
    /// the tenant row plus <see cref="IEntitlementSource"/>), and the default
    /// NULL-permissions plan (or an unknown / null plan) resolves to unrestricted,
    /// so every non-owner-reserved permission stays grantable and no existing test
    /// changes. MUST run inside the caller's open transaction so the RLS GUC is set
    /// for the tenant-plan read.
    /// </summary>
    private async Task<Error?> ValidatePlanPermissionsAsync(
        List<string> permissions, CancellationToken cancellationToken)
    {
        if (permissions.Count == 0)
        {
            return null;
        }

        var resolved = await ResolveTenantPlanAsync(db, cancellationToken);
        foreach (var permission in permissions)
        {
            if (!resolved.AllowsPermission(permission))
            {
                return new Error(
                    ErrorKind.Validation,
                    "tenancy.permission_not_in_plan",
                    $"'{permission}' is not included in this tenant's plan.");
            }
        }

        return null;
    }

    /// <summary>
    /// Resolves the active tenant's commercial entitlements from the plan key on the
    /// supplied context's tenant row plus <see cref="IEntitlementSource"/>, exactly
    /// as <c>GetCallerEntitlementsAsync</c> does. MUST run inside the caller's open
    /// transaction so the RLS GUC is set for the tenant-plan read; the context is a
    /// parameter so the seeding path can resolve on its own bypass context.
    /// </summary>
    private async Task<Entitlements> ResolveTenantPlanAsync(
        TenancyDbContext context, CancellationToken cancellationToken)
    {
        var planKey = await context.Tenants
            .AsNoTracking()
            .Select(t => t.Plan)
            .SingleOrDefaultAsync(cancellationToken);
        return await entitlements.ResolveAsync(planKey, cancellationToken);
    }

    private static Error? ValidatePermissions(IReadOnlyCollection<string> permissions)
    {
        foreach (var permission in permissions)
        {
            if (!Permissions.IsKnown(permission))
            {
                return new Error(
                    ErrorKind.Validation,
                    "tenancy.permission_unknown",
                    $"'{permission}' is not a known permission.");
            }

            if (Permissions.IsOwnerReserved(permission))
            {
                return new Error(
                    ErrorKind.Validation,
                    "tenancy.permission_reserved",
                    $"'{permission}' is owner-reserved and cannot be granted in a custom role.");
            }
        }

        return null;
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
