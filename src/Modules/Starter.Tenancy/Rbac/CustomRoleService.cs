using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
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
    Clock clock)
{
    // --- Roles ------------------------------------------------------------

    public async Task<Result<Guid>> CreateRoleAsync(
        Guid callerUserId,
        string key,
        string name,
        string? description,
        string assignableAt,
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

        var distinctPermissions = Distinct(permissions);
        if (ValidatePermissions(distinctPermissions) is { } permissionError)
        {
            return Result.Failure<Guid>(permissionError);
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Tenant-owned roles only this increment, so the duplicate check is on
        // (tenant, workspace=null, key); the unique index is the race backstop.
        var duplicate = await db.Roles
            .AsNoTracking()
            .AnyAsync(role => role.WorkspaceId == null && role.Key == key, cancellationToken);
        if (duplicate)
        {
            return Result.Failure<Guid>(RoleKeyTaken);
        }

        var roleRow = new CustomRole
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            Key = key,
            Name = name,
            Description = description,
            AssignableAt = assignableAt,
            WorkspaceId = null,
            CreatedBy = callerUserId,
            CreatedAt = now,
        };
        db.Roles.Add(roleRow);
        foreach (var permission in distinctPermissions)
        {
            db.RolePermissions.Add(new RolePermission
            {
                RoleId = roleRow.Id,
                TenantId = tenant.TenantId,
                Permission = permission,
            });
        }

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(RoleKeyTaken);
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.RoleCreated(roleRow.Id, key, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(roleRow.Id);
    }

    public async Task<IReadOnlyList<(Guid Id, string Key, string Name, string? Description, string AssignableAt, DateTimeOffset CreatedAt)>>
        ListRolesAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Roles
            .AsNoTracking()
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
        Guid principalUserId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var role = await db.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, cancellationToken);
        if (role is null)
        {
            return Result.Failure<Guid>(RoleNotFound);
        }

        // The scope must be one the role author allowed (tenant scope only this
        // increment); a role that is workspace-only cannot be granted tenant-wide.
        if (!RoleAssignableAt.Allows(role.AssignableAt, AssignmentScope.Tenant))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.scope_not_assignable",
                "This role cannot be assigned at tenant scope."));
        }

        // The principal must be an active member of the tenant (RLS-scoped read).
        var isActiveMember = await db.Memberships
            .AsNoTracking()
            .AnyAsync(
                membership => membership.UserId == principalUserId
                    && membership.Status == MembershipStatus.Active,
                cancellationToken);
        if (!isActiveMember)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.principal_not_member",
                "The target user is not an active member of this tenant."));
        }

        var alreadyAssigned = await db.RoleAssignments
            .AsNoTracking()
            .AnyAsync(
                assignment => assignment.PrincipalType == PrincipalType.User
                    && assignment.PrincipalId == principalUserId
                    && assignment.RoleId == roleId
                    && assignment.ScopeType == AssignmentScope.Tenant,
                cancellationToken);
        if (alreadyAssigned)
        {
            return Result.Failure<Guid>(AssignmentExists);
        }

        var assignmentRow = new RoleAssignment
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            PrincipalType = PrincipalType.User,
            PrincipalId = principalUserId,
            RoleId = roleId,
            ScopeType = AssignmentScope.Tenant,
            ScopeId = null,
            GrantedBy = callerUserId,
            CreatedAt = now,
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
            TenancyEvents.RoleAssignmentGranted(assignmentRow.Id, roleId, principalUserId, callerUserId, now),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);

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

    public async Task<IReadOnlyList<(Guid Id, Guid RoleId, string PrincipalType, Guid PrincipalId, string ScopeType, Guid? ScopeId, DateTimeOffset CreatedAt)>>
        ListAssignmentsAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.RoleAssignments
            .AsNoTracking()
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
                assignment.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (
                row.Id, row.RoleId, row.PrincipalType, row.PrincipalId, row.ScopeType, row.ScopeId, row.CreatedAt))
            .ToList();
    }

    // --- Helpers ----------------------------------------------------------

    private static readonly Error RoleNotFound = new(
        ErrorKind.NotFound, "tenancy.role_not_found", "No such custom role.");

    private static readonly Error RoleKeyTaken = new(
        ErrorKind.Conflict, "tenancy.role_key_taken", "A role with that key already exists.");

    private static readonly Error RoleInUse = new(
        ErrorKind.Conflict, "tenancy.role_in_use", "The role has assignments; revoke them before deleting it.");

    private static readonly Error AssignmentExists = new(
        ErrorKind.Conflict, "tenancy.assignment_exists", "That role is already assigned to the principal at this scope.");

    private static List<string> Distinct(IReadOnlyCollection<string> permissions) =>
        permissions
            .Where(permission => !string.IsNullOrWhiteSpace(permission))
            .Select(permission => permission.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

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
