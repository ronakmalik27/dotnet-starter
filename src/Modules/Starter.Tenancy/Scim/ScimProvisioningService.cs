using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Scim;

/// <summary>
/// The SCIM 2.0 Users provisioning core (sso-and-scim.md section 5), mapping SCIM
/// Users onto tenant memberships over the ACTIVE tenant on the REQUEST path under
/// row-level security. The SCIM principal carries the resolved tid (bound by
/// <c>TenantResolutionMiddleware</c>), so every membership read and write here is
/// RLS-scoped to the token's tenant: a member of ANOTHER tenant is invisible and
/// reads as 404, and cross-tenant isolation holds with no code of its own.
/// <para>
/// The global user is resolved (or created born-unverified) through the
/// <see cref="IUserProvisioner"/> platform port - the tenancy module never touches
/// the identity schema directly - and the email is read back through
/// <see cref="IUserDirectory"/>. Member deactivate/reactivate is a genuine soft
/// status flip in place (Active &lt;-&gt; Suspended), preserving the row and its
/// grants; DELETE is soft, never a hard delete. The last-owner guard
/// (<see cref="MembershipQueries.IsLastOwnerAsync"/>) refuses suspending a tenant's
/// last owner, so a directory offboard can never lock a tenant out.
/// </para>
/// </summary>
internal sealed class ScimProvisioningService(
    TenancyDbContext db,
    ITenantContext tenant,
    IUserProvisioner userProvisioner,
    IUserDirectory users,
    OutboxWriter outbox,
    Clock clock)
{
    /// <summary>The resolved SCIM view of a member: our global user id, the email, the active flag, and the round-tripped externalId.</summary>
    public readonly record struct ScimMemberView(Guid UserId, string Email, bool Active, string? ExternalId);

    /// <summary>
    /// POST /Users: resolve-or-create the global user (born unverified, passwordless -
    /// so a later first SSO login claims the shell), then ensure a member of the
    /// token's tenant. Idempotent on email: a repeat provision returns the existing
    /// member with no duplicate. <paramref name="externalId"/> is stored on a genuine
    /// create so a SCIM client's stable handle round-trips. Emits
    /// <c>tenancy.membership.created</c> only on a fresh membership.
    /// </summary>
    public async Task<Result<(ScimMemberView View, bool Created)>> ProvisionAsync(
        string userName, string? externalId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeEmail(userName, out var email))
        {
            return Result.Failure<(ScimMemberView, bool)>(new Error(
                ErrorKind.Validation, "tenancy.scim_username_invalid", "userName must be a valid email address."));
        }

        // Resolve-or-create the global user FIRST, on the identity connection through
        // the platform port (users are global, no tenant), before opening the tenant
        // transaction - exactly as the invite flow resolves the user outside its
        // tenant transaction.
        var userId = await userProvisioner.EnsureProvisionedUserAsync(email, cancellationToken);
        var now = clock.UtcNow;
        var membershipId = Ids.NewId(now);

        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

            var existing = await db.Memberships
                .AsNoTracking()
                .SingleOrDefaultAsync(membership => membership.UserId == userId, cancellationToken);
            if (existing is not null)
            {
                // Already a member (any status): idempotent ensure, no second event,
                // no mutation. The existing externalId and status round-trip.
                await transaction.CommitAsync(cancellationToken);
                return Result.Success((
                    new ScimMemberView(userId, email, IsActive(existing.Status), existing.ScimExternalId),
                    false));
            }

            db.Memberships.Add(new Membership
            {
                Id = membershipId,
                TenantId = tenant.TenantId,
                UserId = userId,
                // Default member role: SCIM provisions a directory user IN; role/team
                // elevation is a separate act (SCIM->role mapping is a grow-into).
                Role = MembershipRole.Member,
                Status = MembershipStatus.Active,
                InvitedBy = null,
                ScimExternalId = externalId,
                CreatedAt = now,
            });
            await db.SaveChangesAsync(cancellationToken);

            await outbox.EnqueueAsync(
                db,
                TenancyEvents.MembershipCreated(membershipId, tenant.TenantId, userId, MembershipRole.Member, now),
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result.Success((new ScimMemberView(userId, email, Active: true, externalId), true));
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // A concurrent provision won the unique (tenant_id, user_id) index. Benign:
            // re-read on a fresh transaction and return the ensure view (no event).
            db.ChangeTracker.Clear();
            var raced = await ReadMembershipViewAsync(userId, email, cancellationToken);
            return raced is { } view
                ? Result.Success((view, false))
                : Result.Failure<(ScimMemberView, bool)>(MemberNotFound);
        }
    }

    /// <summary>
    /// GET /Users/{id}: the SCIM view for a member of the token's tenant, or null when
    /// no such member exists here (including a user who is a member of ANOTHER tenant
    /// only - RLS makes their membership invisible, so it reads as 404).
    /// </summary>
    public Task<ScimMemberView?> GetAsync(Guid userId, CancellationToken cancellationToken) =>
        ReadMembershipViewAsync(userId, email: null, cancellationToken);

    /// <summary>
    /// GET /Users?filter=userName eq "...": resolves the userName (email) to a global
    /// user, then returns that user's member view for the token's tenant, or null when
    /// the email is unknown or is not a member here. This is the ONLY supported filter.
    /// </summary>
    public async Task<ScimMemberView?> FindByUserNameAsync(string userName, CancellationToken cancellationToken)
    {
        if (!TryNormalizeEmail(userName, out var email))
        {
            return null;
        }

        var userId = await users.FindUserIdByEmailAsync(email, cancellationToken);
        return userId is Guid id ? await ReadMembershipViewAsync(id, email, cancellationToken) : null;
    }

    /// <summary>
    /// The shared soft deactivate/reactivate core (sso-and-scim.md section 5): flips
    /// <c>Membership.Status</c> in place (Active &lt;-&gt; Suspended), preserving the
    /// row, role, role assignments, and team memberships. SCIM PUT active=false and
    /// DELETE both drive suspend; PUT active=true drives reactivate. Idempotent - a
    /// no-op when already in the target state (directory syncs retry relentlessly).
    /// Suspend is guarded by <see cref="MembershipQueries.IsLastOwnerAsync"/>: the last
    /// owner is never suspended, returning a conflict rather than a lockout. No
    /// authorization-layer change is needed - the resolvers already fail closed on any
    /// non-Active status, so a suspended member's role and team grants resolve empty.
    /// </summary>
    public async Task<Result<ScimMemberView>> SetActiveAsync(
        Guid userId, bool active, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var membership = await db.Memberships.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId, cancellationToken);
        if (membership is null)
        {
            return Result.Failure<ScimMemberView>(MemberNotFound);
        }

        var targetStatus = active ? MembershipStatus.Active : MembershipStatus.Suspended;
        if (membership.Status == targetStatus)
        {
            // Idempotent no-op: already in the target state. Mirrors
            // ServiceAccountService.RevokeAsync's benign-success stance.
            await transaction.CommitAsync(cancellationToken);
            return await BuildViewResultAsync(membership, cancellationToken);
        }

        if (!active
            && membership.Role == MembershipRole.Owner
            && await MembershipQueries.IsLastOwnerAsync(db, cancellationToken))
        {
            // Never suspend the tenant's last owner: a directory offboard must not be
            // able to lock a tenant out of its own control plane.
            return Result.Failure<ScimMemberView>(LastOwner);
        }

        membership.Status = targetStatus;
        await db.SaveChangesAsync(cancellationToken);

        // A SCIM deactivate/reactivate is directory-driven: there is no interactive
        // user actor, so the event carries a null actor (the affected user rides the
        // payload). Recording the affected user as the actor would misread as "the
        // member deactivated themselves" in the audit log.
        var domainEvent = active
            ? TenancyEvents.MemberReactivated(membership.Id, userId, actorUserId: null, now)
            : TenancyEvents.MemberSuspended(membership.Id, userId, actorUserId: null, now);
        await outbox.EnqueueAsync(db, domainEvent, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return await BuildViewResultAsync(membership, cancellationToken);
    }

    // Reads a member's view inside an RLS-bound transaction. When the email is already
    // known (the provision/find paths pass it) the identity lookup is skipped;
    // otherwise it is read through IUserDirectory. Returns null when the user is not a
    // member of the active tenant, or the email cannot be resolved.
    private async Task<ScimMemberView?> ReadMembershipViewAsync(
        Guid userId, string? email, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var membership = await db.Memberships
            .AsNoTracking()
            .Where(candidate => candidate.UserId == userId)
            .Select(candidate => new { candidate.Status, candidate.ScimExternalId })
            .SingleOrDefaultAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        if (membership is null)
        {
            return null;
        }

        var resolvedEmail = email ?? await users.GetEmailAsync(userId, cancellationToken);
        return resolvedEmail is null
            ? null
            : new ScimMemberView(userId, resolvedEmail, IsActive(membership.Status), membership.ScimExternalId);
    }

    private async Task<Result<ScimMemberView>> BuildViewResultAsync(
        Membership membership, CancellationToken cancellationToken)
    {
        var email = await users.GetEmailAsync(membership.UserId, cancellationToken);
        return email is null
            ? Result.Failure<ScimMemberView>(MemberNotFound)
            : Result.Success(new ScimMemberView(
                membership.UserId, email, IsActive(membership.Status), membership.ScimExternalId));
    }

    private static bool IsActive(string status) =>
        string.Equals(status, MembershipStatus.Active, StringComparison.Ordinal);

    // A minimal, dependency-free email check: the tenancy module cannot reach the
    // identity module's EmailAddress validator (module boundary), and Okta / Azure AD
    // always send a real email as userName, so a non-blank value carrying '@' and '.'
    // is the right bar for a seam. Deeper shape validation is the IdP's job.
    private static bool TryNormalizeEmail(string? userName, out string email)
    {
        email = userName?.Trim() ?? string.Empty;
        return email.Length > 0
            && email.Contains('@', StringComparison.Ordinal)
            && email.Contains('.', StringComparison.Ordinal);
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    private static readonly Error MemberNotFound = new(
        ErrorKind.NotFound, "tenancy.scim_member_not_found", "No such member.");

    private static readonly Error LastOwner = new(
        ErrorKind.Conflict, "tenancy.last_owner", "The last owner cannot be deactivated.");
}
