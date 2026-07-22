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

        var (row, rawToken) = InvitationPolicy.Issue(tenant.TenantId, email, role, callerUserId, now);
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
        CancellationToken cancellationToken)
    {
        name = name?.Trim();
        slug = slug?.Trim();
        if (string.IsNullOrEmpty(name) && string.IsNullOrEmpty(slug))
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.no_settings", "Provide a name and/or a slug to update."));
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
        // usable.
        tenantRow.Status = TenantStatus.Deleted;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TenantSoftDeleted(tenant.TenantId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Seats ------------------------------------------------------------

    public async Task<(int SeatLimit, int ActiveMembers)> GetSeatsAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var seatLimit = await db.Tenants
            .AsNoTracking()
            .Select(tenantRow => (int?)tenantRow.SeatLimit)
            .SingleOrDefaultAsync(cancellationToken) ?? 0;
        var activeMembers = await db.Memberships
            .AsNoTracking()
            .CountAsync(membership => membership.Status == MembershipStatus.Active, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return (seatLimit, activeMembers);
    }

    private static readonly Error LastOwner = new(
        ErrorKind.Conflict, "tenancy.last_owner", "The last owner cannot be removed or demoted.");

    private async Task<bool> IsLastOwnerAsync(CancellationToken cancellationToken)
    {
        // Only "is there more than one owner" matters, so cap the count at 2.
        var owners = await db.Memberships
            .AsNoTracking()
            .Where(membership =>
                membership.Role == MembershipRole.Owner && membership.Status == MembershipStatus.Active)
            .Take(2)
            .CountAsync(cancellationToken);
        return owners <= 1;
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
