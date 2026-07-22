using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// The team control plane (multi-tenancy.md sections 14, 17, 20): create, list,
/// get, rename, and delete teams, plus add/remove/list team members, all
/// operating on the ACTIVE tenant on the REQUEST path under row-level security -
/// NOT the bypass path. A team and its members are tenant-owned, so every read
/// and write opens a transaction (the tenant interceptor sets the current-tenant
/// GUC, RLS then binds it to the active tenant) and a team or user from another
/// tenant is simply invisible.
/// <para>
/// A team is a principal that can hold grants (section 13): the effective-
/// permission resolver unions the grants of every team a caller belongs to. This
/// service owns the team's lifecycle only; assigning a role TO a team is the
/// assignment API on <see cref="CustomRoleService"/>. Deleting a team first
/// removes its role_assignments (principal_type = team) so no grant dangles
/// (section 20); its team_members cascade via the FK. The endpoint's
/// RequirePermission(teams:manage) gate runs before any write here.
/// </para>
/// </summary>
internal sealed class TeamService(
    TenancyDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    Clock clock)
{
    // --- Teams ------------------------------------------------------------

    public async Task<Result<Guid>> CreateTeamAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(slug);
        ArgumentNullException.ThrowIfNull(name);

        slug = slug.Trim();
        name = name.Trim();

        if (slug.Length == 0 || slug.Length > 64)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.team_slug_invalid", "A team slug must be 1-64 characters."));
        }

        if (name.Length == 0)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.team_name_required", "A team name is required."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The slug is unique per tenant (citext); the unique index is the race
        // backstop, this is the friendly pre-check under RLS.
        var duplicate = await db.Teams
            .AsNoTracking()
            .AnyAsync(team => team.Slug == slug, cancellationToken);
        if (duplicate)
        {
            return Result.Failure<Guid>(TeamSlugTaken);
        }

        var row = new Team
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            Slug = slug,
            Name = name,
            CreatedBy = callerUserId,
            CreatedAt = now,
        };
        db.Teams.Add(row);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(TeamSlugTaken);
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.TeamCreated(row.Id, slug, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(row.Id);
    }

    public async Task<IReadOnlyList<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        ListTeamsAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Teams
            .AsNoTracking()
            .OrderBy(team => team.CreatedAt)
            .ThenBy(team => team.Id)
            .Select(team => new { team.Id, team.Slug, team.Name, team.CreatedAt })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.Slug, row.Name, row.CreatedAt))
            .ToList();
    }

    public async Task<Result<(Guid Id, string Slug, string Name, DateTimeOffset CreatedAt)>>
        GetTeamAsync(Guid teamId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var row = await db.Teams
            .AsNoTracking()
            .Where(team => team.Id == teamId)
            .Select(team => new { team.Id, team.Slug, team.Name, team.CreatedAt })
            .SingleOrDefaultAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        if (row is null)
        {
            return Result.Failure<(Guid, string, string, DateTimeOffset)>(TeamNotFound);
        }

        return Result.Success((row.Id, row.Slug, row.Name, row.CreatedAt));
    }

    public async Task<Result> RenameTeamAsync(
        Guid callerUserId, Guid teamId, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);
        name = name.Trim();
        if (name.Length == 0)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.team_name_required", "A team name is required."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var team = await db.Teams.SingleOrDefaultAsync(
            candidate => candidate.Id == teamId, cancellationToken);
        if (team is null)
        {
            return Result.Failure(TeamNotFound);
        }

        team.Name = name;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TeamRenamed(teamId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> DeleteTeamAsync(
        Guid callerUserId, Guid teamId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var team = await db.Teams.SingleOrDefaultAsync(
            candidate => candidate.Id == teamId, cancellationToken);
        if (team is null)
        {
            return Result.Failure(TeamNotFound);
        }

        // Offboard (section 20): remove the team's grants FIRST so no
        // role_assignment dangles (principal_id references a team by value, no FK
        // to cascade). Unlike a custom role - deleting which is refused while in
        // use - a team deletion cascades its own grants, because the doc's team
        // offboarding says "delete removes the team's grants first". The
        // team_members rows cascade via the FK on the team delete below.
        var grants = await db.RoleAssignments
            .Where(assignment =>
                assignment.PrincipalType == PrincipalType.Team && assignment.PrincipalId == teamId)
            .ToListAsync(cancellationToken);
        db.RoleAssignments.RemoveRange(grants);

        db.Teams.Remove(team);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TeamDeleted(teamId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // --- Team members -----------------------------------------------------

    public async Task<Result<Guid>> AddMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var teamExists = await db.Teams
            .AsNoTracking()
            .AnyAsync(team => team.Id == teamId, cancellationToken);
        if (!teamExists)
        {
            return Result.Failure<Guid>(TeamNotFound);
        }

        // A team member must be an active tenant member (RLS-scoped read), exactly
        // as a user-principal grant validates: a team never confers access to a
        // user the tenant would not otherwise admit.
        var isActiveMember = await db.Memberships
            .AsNoTracking()
            .AnyAsync(
                membership => membership.UserId == userId && membership.Status == MembershipStatus.Active,
                cancellationToken);
        if (!isActiveMember)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation,
                "tenancy.principal_not_member",
                "The target user is not an active member of this tenant."));
        }

        var alreadyMember = await db.TeamMembers
            .AsNoTracking()
            .AnyAsync(member => member.TeamId == teamId && member.UserId == userId, cancellationToken);
        if (alreadyMember)
        {
            return Result.Failure<Guid>(TeamMemberExists);
        }

        var row = new TeamMember
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            TeamId = teamId,
            UserId = userId,
            CreatedAt = now,
        };
        db.TeamMembers.Add(row);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(TeamMemberExists);
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.TeamMemberAdded(teamId, userId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(row.Id);
    }

    public async Task<Result> RemoveMemberAsync(
        Guid callerUserId, Guid teamId, Guid userId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var member = await db.TeamMembers.SingleOrDefaultAsync(
            candidate => candidate.TeamId == teamId && candidate.UserId == userId, cancellationToken);
        if (member is null)
        {
            return Result.Failure(new Error(
                ErrorKind.NotFound, "tenancy.team_member_not_found", "No such team member."));
        }

        // Removing a member revokes the team's grants for them on their NEXT
        // request: the resolver reads team membership per request, so nothing more
        // is needed here (no token churn, section 14).
        db.TeamMembers.Remove(member);
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.TeamMemberRemoved(teamId, userId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result<IReadOnlyList<(Guid UserId, DateTimeOffset CreatedAt)>>>
        ListMembersAsync(Guid teamId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var teamExists = await db.Teams
            .AsNoTracking()
            .AnyAsync(team => team.Id == teamId, cancellationToken);
        if (!teamExists)
        {
            return Result.Failure<IReadOnlyList<(Guid, DateTimeOffset)>>(TeamNotFound);
        }

        var rows = await db.TeamMembers
            .AsNoTracking()
            .Where(member => member.TeamId == teamId)
            .OrderBy(member => member.CreatedAt)
            .ThenBy(member => member.Id)
            .Select(member => new { member.UserId, member.CreatedAt })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success<IReadOnlyList<(Guid, DateTimeOffset)>>(
            rows.Select(row => (row.UserId, row.CreatedAt)).ToList());
    }

    // --- Helpers ----------------------------------------------------------

    private static readonly Error TeamNotFound = new(
        ErrorKind.NotFound, "tenancy.team_not_found", "No such team.");

    private static readonly Error TeamSlugTaken = new(
        ErrorKind.Conflict, "tenancy.team_slug_taken", "A team with that slug already exists.");

    private static readonly Error TeamMemberExists = new(
        ErrorKind.Conflict, "tenancy.team_member_exists", "That user is already a member of the team.");

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
