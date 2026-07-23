using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Tenancy.Invitations;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Admin;

/// <summary>
/// The tenant-admin control plane (multi-tenancy.md section 8), all operating on
/// the ACTIVE tenant on the REQUEST path under row-level security - NOT the
/// bypass path. Every write opens a transaction so the tenant interceptor sets
/// the current-tenant GUC (RLS then binds every read and write to the active
/// tenant), stamps its domain event through the OutboxWriter (which reads the
/// same tenant), and commits once. Role gating (admin+, owner-only where noted)
/// is enforced by the endpoint's RequireTenantRole gate before this runs; the
/// business rules here are the ones RLS and roles do not express: last-owner
/// protection, self-target rules, and the assignable-role set.
/// </summary>
internal sealed class TenantAdminService(
    TenancyDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    IEntitlementSource entitlements,
    IPolicyDefaults policyDefaults,
    Clock clock,
    InvitationEmailComposer invitationEmail,
    IUserDirectory users,
    ILogger<TenantAdminService> logger)
{
    // --- Members ----------------------------------------------------------

    public async Task<IReadOnlyList<(Guid UserId, string Role, string Status, DateTimeOffset CreatedAt)>>
        ListMembersAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Memberships
            .AsNoTracking()
            .OrderBy(membership => membership.CreatedAt)
            .ThenBy(membership => membership.Id)
            .Select(membership => new
            {
                membership.UserId,
                membership.Role,
                membership.Status,
                membership.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.UserId, row.Role, row.Status, row.CreatedAt))
            .ToList();
    }

    public async Task<Result> ChangeMemberRoleAsync(
        Guid callerUserId,
        Guid targetUserId,
        string role,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(role);

        if (role == MembershipRole.Owner)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "tenancy.cannot_promote_to_owner",
                "Promoting to owner is transfer-ownership, not a role change."));
        }

        if (!MembershipRoles.IsAssignable(role))
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.invalid_role", "A member role must be admin or member."));
        }

        if (targetUserId == callerUserId)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.cannot_change_own_role", "You cannot change your own role."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var target = await db.Memberships.SingleOrDefaultAsync(
            membership => membership.UserId == targetUserId && membership.Status == MembershipStatus.Active,
            cancellationToken);
        if (target is null)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.member_not_found", "No such active member."));
        }

        if (target.Role == MembershipRole.Owner && await IsLastOwnerAsync(cancellationToken))
        {
            return Result.Failure(LastOwner);
        }

        target.Role = role;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.MemberRoleChanged(target.Id, targetUserId, role, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> RemoveMemberAsync(
        Guid callerUserId,
        Guid targetUserId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var target = await db.Memberships.SingleOrDefaultAsync(
            membership => membership.UserId == targetUserId && membership.Status == MembershipStatus.Active,
            cancellationToken);
        if (target is null)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.member_not_found", "No such active member."));
        }

        // Removing the last owner is refused (including the owner removing
        // themselves); ownership moves through transfer-ownership. A member or
        // admin may remove themselves, since they are never the last owner.
        if (target.Role == MembershipRole.Owner && await IsLastOwnerAsync(cancellationToken))
        {
            return Result.Failure(LastOwner);
        }

        // Hard delete: the audit lives on the event spine, so the row itself
        // need not linger (the brief's sanctioned choice).
        db.Memberships.Remove(target);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.MemberRemoved(target.Id, targetUserId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Invitations ------------------------------------------------------

    public async Task<Result<Guid>> InviteMemberAsync(
        Guid callerUserId,
        string email,
        string role,
        Guid? workspaceId,
        Guid? roleId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(role);

        email = email.Trim();
        if (email.Length == 0)
        {
            return Result.Failure<Guid>(
                new Error(ErrorKind.Validation, "tenancy.email_required", "An invite email is required."));
        }

        if (!MembershipRoles.IsAssignable(role))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.invalid_role", "An invited role must be admin or member."));
        }

        // A scope-aware invite (section 16) carries workspace_id + role_id
        // TOGETHER: the scoped role to grant, in that workspace, on accept. One
        // without the other is a malformed invite.
        if (workspaceId is null != (roleId is null))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.invite_scope_incomplete",
                "A scope-aware invite requires both a workspaceId and a roleId, or neither."));
        }

        // Users are global (no tenant), so this lookup runs outside the tenant
        // transaction; the membership check below runs inside it under RLS.
        var existingUserId = await users.FindUserIdByEmailAsync(email, cancellationToken);

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        if (existingUserId is Guid userId)
        {
            var alreadyMember = await db.Memberships
                .AsNoTracking()
                .AnyAsync(
                    membership => membership.UserId == userId && membership.Status == MembershipStatus.Active,
                    cancellationToken);
            if (alreadyMember)
            {
                return Result.Failure<Guid>(new Error(
                    ErrorKind.Conflict, "tenancy.already_member", "That account is already a member."));
            }
        }

        var pendingExists = await db.Invitations
            .AsNoTracking()
            .AnyAsync(
                invitation =>
                    invitation.Email == email && invitation.AcceptedAt == null && invitation.ExpiresAt > now,
                cancellationToken);
        if (pendingExists)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Conflict, "tenancy.already_member", "That email already has a pending invitation."));
        }

        // Validate the scoped role at invite time, the SAME scope guardrails as a
        // direct grant (section 13): the role must exist, the workspace must
        // exist, the role must be assignable at workspace scope, and a
        // workspace-local role must own that same workspace. So an invitation can
        // never bind a role wider than its scope, and the accept path can trust
        // the stored pair. All reads are RLS-scoped to the active tenant.
        if (workspaceId is Guid inviteWorkspace && roleId is Guid inviteRole)
        {
            if (await ValidateInviteScopeAsync(inviteWorkspace, inviteRole, cancellationToken) is { } scopeError)
            {
                return Result.Failure<Guid>(scopeError);
            }
        }

        var (row, rawToken) = InvitationPolicy.Issue(
            tenant.TenantId, email, role, callerUserId, now, workspaceId, roleId);
        db.Invitations.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.InvitationCreated(row.Id, role, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        // Post-commit, best-effort: the invitation exists even if the email
        // fails; an admin can re-invite. The raw token reaches the invitee only
        // through this link, never on the event spine.
        try
        {
            await invitationEmail.SendInvitationEmailAsync(email, rawToken, cancellationToken);
        }
        catch (Exception exception)
        {
            InvitationEmailLog.DispatchFailed(logger, exception);
        }

        return Result.Success(row.Id);
    }

    public async Task<IReadOnlyList<(Guid Id, string Email, string Role, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt)>>
        ListInvitationsAsync(CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Invitations
            .AsNoTracking()
            .Where(invitation => invitation.AcceptedAt == null && invitation.ExpiresAt > now)
            .OrderBy(invitation => invitation.CreatedAt)
            .ThenBy(invitation => invitation.Id)
            .Select(invitation => new
            {
                invitation.Id,
                invitation.Email,
                invitation.Role,
                invitation.ExpiresAt,
                invitation.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.Email, row.Role, row.ExpiresAt, row.CreatedAt))
            .ToList();
    }

    public async Task<Result> RevokeInvitationAsync(
        Guid callerUserId,
        Guid invitationId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var invitation = await db.Invitations.SingleOrDefaultAsync(
            candidate => candidate.Id == invitationId && candidate.AcceptedAt == null, cancellationToken);
        if (invitation is null)
        {
            return Result.Failure(new Error(
                ErrorKind.NotFound, "tenancy.invitation_not_found", "No such pending invitation."));
        }

        db.Invitations.Remove(invitation);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.InvitationRevoked(invitationId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Settings ---------------------------------------------------------

    public async Task<Result> UpdateSettingsAsync(
        Guid callerUserId,
        string? name,
        string? slug,
        int? sessionMaxSeconds,
        CancellationToken cancellationToken)
    {
        name = name?.Trim();
        slug = slug?.Trim();
        if (string.IsNullOrEmpty(name) && string.IsNullOrEmpty(slug) && sessionMaxSeconds is null)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.no_settings", "Provide a name, a slug, and/or a session lifetime to update."));
        }

        if (name is not null && name.Length == 0)
        {
            return Result.Failure(
                new Error(ErrorKind.Validation, "tenancy.name_required", "A tenant name cannot be empty."));
        }

        if (slug is not null && !TenantSlugs.IsValid(slug))
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "tenancy.slug_invalid",
                "A tenant slug must be 1-63 characters of letters, digits, and hyphens."));
        }

        // The session-lifetime override may only TIGHTEN
        // (role-templates-and-policy-defaults.md section 5): a positive value no
        // longer than the platform access-token lifetime. A longer value is rejected
        // (a shorter token lifetime is tighter/safer); the effective tid lifetime is
        // min(platform default, override), enforced at the mint. This is the one
        // coherent tenant override in the global-user model.
        if (sessionMaxSeconds is int requestedSession)
        {
            if (requestedSession < 1)
            {
                return Result.Failure(new Error(
                    ErrorKind.Validation,
                    "tenancy.session_invalid",
                    "A session lifetime must be a positive number of seconds."));
            }

            var platformMax = (await policyDefaults.GetAsync(cancellationToken)).AccessTokenLifetimeSeconds;
            if (requestedSession > platformMax)
            {
                return Result.Failure(new Error(
                    ErrorKind.Validation,
                    "tenancy.session_longer_than_platform",
                    $"A tenant session lifetime may not exceed the platform maximum of {platformMax} seconds."));
            }
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenantRow = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenantRow is null)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.tenant_not_found", "The tenant does not exist."));
        }

        if (!string.IsNullOrEmpty(name))
        {
            tenantRow.Name = name;
        }

        if (!string.IsNullOrEmpty(slug))
        {
            tenantRow.Slug = slug;
        }

        if (sessionMaxSeconds is int seconds)
        {
            tenantRow.SessionMaxSeconds = seconds;
        }

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // The slug's citext unique index fired: another tenant holds it. A
            // slug is caller-supplied and not a secret, so a definite 409 is fine.
            return Result.Failure(
                new Error(ErrorKind.Conflict, "tenancy.slug_taken", "That tenant slug is already taken."));
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantSettingsUpdated(tenant.TenantId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Ownership and lifecycle -----------------------------------------

    public async Task<Result> TransferOwnershipAsync(
        Guid callerUserId,
        Guid targetUserId,
        CancellationToken cancellationToken)
    {
        if (targetUserId == callerUserId)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.cannot_transfer_to_self", "You already own this tenant."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var caller = await db.Memberships.SingleOrDefaultAsync(
            membership => membership.UserId == callerUserId && membership.Status == MembershipStatus.Active,
            cancellationToken);
        // The gate guarantees the caller is the owner; re-check defensively.
        if (caller is null || caller.Role != MembershipRole.Owner)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.member_not_found", "No such active owner."));
        }

        var target = await db.Memberships.SingleOrDefaultAsync(
            membership => membership.UserId == targetUserId && membership.Status == MembershipStatus.Active,
            cancellationToken);
        if (target is null)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.member_not_found", "No such active member."));
        }

        // Single-owner model: the new owner is promoted and the previous owner
        // steps down to admin, in one transaction.
        target.Role = MembershipRole.Owner;
        caller.Role = MembershipRole.Admin;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db,
            TenancyEvents.OwnershipTransferred(tenant.TenantId, targetUserId, callerUserId, now),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> SoftDeleteTenantAsync(Guid callerUserId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var tenantRow = await db.Tenants.SingleOrDefaultAsync(cancellationToken);
        if (tenantRow is null)
        {
            return Result.Failure(
                new Error(ErrorKind.NotFound, "tenancy.tenant_not_found", "The tenant does not exist."));
        }

        // Soft-delete via status, never a hard row delete (audit). Memberships
        // are left intact this increment; a deleted tenant simply stops being
        // usable. Stamp deleted_at: the DSAR retention window is measured from it,
        // and reactivate clears it (data-export-and-erasure.md section 2).
        tenantRow.Status = TenantStatus.Deleted;
        tenantRow.DeletedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantSoftDeleted(tenant.TenantId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    /// <summary>
    /// Records a completed self-serve data export (data-export-and-erasure.md section
    /// 6): enqueues <c>tenancy.tenant.data_exported</c> on the active tenant's spine
    /// (audited and webhook-deliverable) with a per-section row-count summary and no
    /// data copy. Runs on the request path under RLS - the endpoint has already read
    /// the bundle through the export service; this is the audit trail for the access.
    /// </summary>
    public async Task<Result> RecordDataExportAsync(
        Guid callerUserId, IReadOnlyDictionary<string, int> sectionCounts, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantDataExported(tenant.TenantId, callerUserId, sectionCounts, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Seats ------------------------------------------------------------

    public async Task<(int SeatLimit, int ActiveMembers, string? Plan, IReadOnlyDictionary<string, int> Limits)>
        GetSeatsAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var row = await db.Tenants
            .AsNoTracking()
            .Select(tenantRow => new { tenantRow.SeatLimit, tenantRow.Plan })
            .SingleOrDefaultAsync(cancellationToken);
        var activeMembers = await db.Memberships
            .AsNoTracking()
            .CountAsync(membership => membership.Status == MembershipStatus.Active, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        // The seats view reports the plan-derived seat limit plus the tenant's plan
        // and its declared numeric limits (billing-and-entitlements.md sections 5,
        // 7). Entitlements resolve off the no-RLS plan catalogue, so this read
        // happens after the tenant transaction commits.
        var planKey = row?.Plan;
        var resolved = await entitlements.ResolveAsync(planKey, cancellationToken);
        return (row?.SeatLimit ?? 0, activeMembers, planKey, resolved.Limits);
    }

    /// <summary>
    /// The caller's full entitlement picture (billing-and-entitlements.md section
    /// 3): reads the ACTIVE tenant's plan under RLS (the GetSeatsAsync pattern - an
    /// explicit read transaction so the tenant GUC is set), then resolves it via
    /// <see cref="IEntitlementSource"/>. A null / unknown plan resolves to
    /// unrestricted (fail open).
    /// </summary>
    public async Task<Entitlements> GetCallerEntitlementsAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var planKey = await db.Tenants
            .AsNoTracking()
            .Select(tenantRow => tenantRow.Plan)
            .SingleOrDefaultAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return await entitlements.ResolveAsync(planKey, cancellationToken);
    }

    /// <summary>
    /// Validates a scope-aware invite's workspace + role pair against the section
    /// 13 grant rules (the workspace exists, the role exists, the role is
    /// assignable at workspace scope, and a workspace-local role owns that
    /// workspace). Returns null when the pair is a valid workspace-scope grant, or
    /// the specific validation error. All reads are RLS-scoped to the active
    /// tenant, so a workspace or role from another tenant reads as "not found".
    /// </summary>
    private async Task<Error?> ValidateInviteScopeAsync(
        Guid workspaceId, Guid roleId, CancellationToken cancellationToken)
    {
        var workspaceExists = await db.Workspaces
            .AsNoTracking()
            .AnyAsync(workspace => workspace.Id == workspaceId, cancellationToken);
        if (!workspaceExists)
        {
            return new Error(ErrorKind.NotFound, "tenancy.workspace_not_found", "No such workspace.");
        }

        var role = await db.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, cancellationToken);
        if (role is null)
        {
            return new Error(ErrorKind.NotFound, "tenancy.role_not_found", "No such custom role.");
        }

        // A workspace-local role can only be granted at its own workspace (the
        // section 13 rule), so a scope-aware invite must name that same workspace.
        if (role.WorkspaceId is Guid roleWorkspace && roleWorkspace != workspaceId)
        {
            return new Error(
                ErrorKind.Validation,
                "tenancy.workspace_role_scope",
                "A workspace-local role can only be assigned at its own workspace.");
        }

        // The role author must have allowed workspace-scope assignment.
        if (!RoleAssignableAt.Allows(role.AssignableAt, AssignmentScope.Workspace))
        {
            return new Error(
                ErrorKind.Validation,
                "tenancy.scope_not_assignable",
                "This role cannot be assigned at workspace scope.");
        }

        return null;
    }

    private static readonly Error LastOwner = new(
        ErrorKind.Conflict, "tenancy.last_owner", "The last owner cannot be removed or demoted.");

    // The last-owner guard is the shared MembershipQueries helper, so the SCIM
    // deactivate path enforces the exact same rule as the admin member ops.
    private Task<bool> IsLastOwnerAsync(CancellationToken cancellationToken) =>
        MembershipQueries.IsLastOwnerAsync(db, cancellationToken);

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
