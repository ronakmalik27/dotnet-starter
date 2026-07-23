using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Tenancy.Invitations;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Accepting an invitation (multi-tenancy.md section 8): CROSS-TENANT
/// control-plane work on the bypass path, because the invitee is by definition
/// not yet a member and holds no tid or role for the target tenant, so an
/// RLS-bound lookup keyed on the current-tenant GUC would see nothing. This is
/// the third Tenancy type the bypass-containment arch test allowlists, alongside
/// the self-serve provisioner and the membership directory.
/// <para>
/// The seat check is race-proof by construction: in one transaction the tenant
/// row is locked (<c>SELECT ... FOR UPDATE</c>), the active-member count is read
/// under that lock, the invitation is consumed (single-use), and the membership
/// is inserted (the unique (tenant_id, user_id) index also guards a double
/// accept). Two concurrent accepts serialize on the tenant row, so the count can
/// never overrun seat_limit. Defense in depth above possession of the token: the
/// authenticated caller's email must match the invitation email (citext-equal),
/// so a leaked link is not redeemable by a different account. Every validation
/// miss - unknown, accepted, expired, or wrong email - collapses to one generic
/// outcome so a holder cannot probe which invitations exist.
/// </para>
/// <para>
/// A scope-aware invitation (multi-tenancy.md section 16) also carries a
/// workspace_id + role_id; when present, the matching workspace-scoped
/// role_assignment is created in the SAME one transaction as the membership,
/// consume, and event, so the invitee lands both a member and their scoped role
/// atomically. The role was validated at invite time, so accept simply binds it.
/// </para>
/// </summary>
internal sealed class InvitationAcceptor(
    BypassDataSource bypass,
    IUserDirectory users,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error Invalid = new(
        ErrorKind.NotFound,
        "tenancy.invitation_invalid",
        "The invitation is not valid, has expired, or is not addressed to this account.");

    public async Task<Result<(Guid TenantId, string Role)>> AcceptAsync(
        Guid userId,
        string token,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Result.Failure<(Guid, string)>(Invalid);
        }

        // The caller's own email (global read, no tenant): the invitation must be
        // addressed to it. A caller with no account resolves to the generic miss.
        var callerEmail = await users.GetEmailAsync(userId, cancellationToken);
        if (callerEmail is null)
        {
            return Result.Failure<(Guid, string)>(Invalid);
        }

        var tokenHash = InvitationTokenSecrets.Hash(token);
        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);

        // Read the invitation by token_hash on the bypass source (no tenant is
        // bound yet). This SELECT auto-commits; the locking work below opens its
        // own transaction on the same connection.
        var invitation = await ReadInvitationByHashAsync(connection, tokenHash, cancellationToken);
        if (invitation is null
            || invitation.AcceptedAt is not null
            || invitation.ExpiresAt <= now
            || !string.Equals(callerEmail, invitation.Email, StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure<(Guid, string)>(Invalid);
        }

        var options = StarterDbContextOptions.ForConnection<TenancyDbContext>(connection).Options;
        await using var db = new TenancyDbContext(options, ITenantContext.ForTenant(invitation.TenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        // Lock the tenant row so two concurrent accepts serialize here: the
        // second waits until the first commits, then reads the updated count.
        var tenant = await LockTenantAsync(connection, dbTransaction, invitation.TenantId, cancellationToken);
        if (tenant is not { Status: TenantStatus.Active })
        {
            return Result.Failure<(Guid, string)>(Invalid);
        }

        var activeMembers = await CountActiveMembersAsync(
            connection, dbTransaction, invitation.TenantId, cancellationToken);
        if (activeMembers >= tenant.SeatLimit)
        {
            return Result.Failure<(Guid, string)>(new Error(
                ErrorKind.Conflict, "tenancy.seat_limit_reached", "The tenant is at its seat limit."));
        }

        // Consume the invitation (single-use). A zero row count means another
        // accept beat us to it (the token is already consumed): generic miss.
        var consumed = await ConsumeInvitationAsync(
            connection, dbTransaction, invitation.Id, now, cancellationToken);
        if (consumed == 0)
        {
            return Result.Failure<(Guid, string)>(Invalid);
        }

        var membershipId = Ids.NewId(now);
        db.Memberships.Add(new Membership
        {
            Id = membershipId,
            TenantId = invitation.TenantId,
            UserId = userId,
            Role = invitation.Role,
            Status = MembershipStatus.Active,
            InvitedBy = invitation.InvitedBy,
            CreatedAt = now,
        });

        // Scope-aware invitation (multi-tenancy.md section 16): when the invite
        // carries workspace_id + role_id, create the workspace-scoped grant in the
        // SAME transaction as the membership, so the invitee lands both a member
        // and "developer on the staging workspace" atomically. The role was
        // validated at invite time (it exists, is assignable at workspace scope,
        // and a workspace-local role owns that workspace), so accept just binds it.
        // tenant_id is stamped from the invitation's tenant, exactly as the
        // membership row is. principal_type is user (the invitee).
        Guid? scopedAssignmentId = null;
        if (invitation.WorkspaceId is Guid workspaceId && invitation.RoleId is Guid scopedRoleId)
        {
            scopedAssignmentId = Ids.NewId(now);
            db.RoleAssignments.Add(new RoleAssignment
            {
                Id = scopedAssignmentId.Value,
                TenantId = invitation.TenantId,
                PrincipalType = PrincipalType.User,
                PrincipalId = userId,
                RoleId = scopedRoleId,
                ScopeType = AssignmentScope.Workspace,
                ScopeId = workspaceId,
                GrantedBy = invitation.InvitedBy,
                CreatedAt = now,
            });
        }

        try
        {
            // The unique (tenant_id, user_id) index guards a double accept by the
            // same account. On a hit the dispose below rolls back the consume (and
            // any scoped grant) too, so the invitation stays pending and the
            // account stays as it was.
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<(Guid, string)>(new Error(
                ErrorKind.Conflict, "tenancy.already_member", "That account is already a member."));
        }

        await outbox.EnqueueAsync(
            db,
            TenancyEvents.MembershipCreated(membershipId, invitation.TenantId, userId, invitation.Role, now),
            cancellationToken);

        if (scopedAssignmentId is Guid assignmentId && invitation.RoleId is Guid grantedRoleId)
        {
            await outbox.EnqueueAsync(
                db,
                // A scope-aware invitation's grant is always unconditional (abac.md section 6).
                TenancyEvents.RoleAssignmentGranted(
                    assignmentId, grantedRoleId, userId, invitation.InvitedBy, conditionType: null, now),
                cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        return Result.Success((invitation.TenantId, invitation.Role));
    }

    private static async Task<InvitationRow?> ReadInvitationByHashAsync(
        NpgsqlConnection connection, string tokenHash, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select id, tenant_id, email, role, expires_at, accepted_at, invited_by, workspace_id, role_id "
            + "from tenancy.invitations where token_hash = @hash limit 1",
            connection);
        command.Parameters.AddWithValue("hash", tokenHash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new InvitationRow(
            reader.GetGuid(0),
            reader.GetGuid(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            await reader.IsDBNullAsync(5, cancellationToken)
                ? null
                : reader.GetFieldValue<DateTimeOffset>(5),
            reader.GetGuid(6),
            await reader.IsDBNullAsync(7, cancellationToken)
                ? null
                : reader.GetGuid(7),
            await reader.IsDBNullAsync(8, cancellationToken)
                ? null
                : reader.GetGuid(8));
    }

    private static async Task<TenantLock?> LockTenantAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select status, seat_limit from tenancy.tenants where id = @tenant for update",
            connection,
            transaction);
        command.Parameters.AddWithValue("tenant", tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TenantLock(reader.GetString(0), reader.GetInt32(1));
    }

    private static async Task<int> CountActiveMembersAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select count(*) from tenancy.memberships where tenant_id = @tenant and status = 'active'",
            connection,
            transaction);
        command.Parameters.AddWithValue("tenant", tenantId);
        return (int)(long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task<int> ConsumeInvitationAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid invitationId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "update tenancy.invitations set accepted_at = @now "
            + "where id = @id and accepted_at is null",
            connection,
            transaction);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("id", invitationId);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    private sealed record InvitationRow(
        Guid Id,
        Guid TenantId,
        string Email,
        string Role,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? AcceptedAt,
        Guid InvitedBy,
        Guid? WorkspaceId,
        Guid? RoleId);

    private sealed record TenantLock(string Status, int SeatLimit);
}
