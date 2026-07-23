using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The <see cref="ITenantSsoProvisioner"/> implementation: JIT-provisions a
/// membership into the tenant whose IdP just authenticated an SSO user
/// (sso-and-scim.md section 4), run on the bypass data source. It is explicitly
/// cross-tenant: the user holds no tid for the tenant yet (SSO is minting the first
/// one), so an RLS-bound write keyed on the current-tenant GUC would see nothing -
/// exactly like self-serve provisioning and invitation accept establish a
/// membership before any tenant context exists. This is one of the Tenancy types
/// the bypass-containment arch test allowlists.
/// <para>
/// Idempotent by construction: the unique <c>(tenant_id, user_id)</c> index guards a
/// concurrent double-provision, so a duplicate INSERT is caught and treated as a
/// benign "already a member" (no second event). Only a fresh create emits
/// <c>tenancy.membership.created</c>.
/// </para>
/// </summary>
internal sealed class SsoMembershipProvisioner(BypassDataSource bypass, OutboxWriter outbox, Clock clock)
    : ITenantSsoProvisioner
{
    public async Task EnsureMembershipAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        var options = StarterDbContextOptions.ForConnection<TenancyDbContext>(connection).Options;

        // Resolve the context to the SSO tenant, so OutboxWriter stamps
        // MembershipCreated with tenant_id = tenantId. On the BYPASSRLS role the GUC
        // the interceptor sets is harmless and the insert is not RLS-checked.
        await using var db = new TenancyDbContext(options, ITenantContext.ForTenant(tenantId));
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var alreadyMember = await db.Memberships
            .AsNoTracking()
            .AnyAsync(membership => membership.UserId == userId, cancellationToken);
        if (alreadyMember)
        {
            // Idempotent: the user is already a member of this tenant (a returning
            // SSO sign-in, or a member who also has SSO). Nothing to do.
            await transaction.CommitAsync(cancellationToken);
            return;
        }

        var membershipId = Ids.NewId(now);
        db.Memberships.Add(new Membership
        {
            Id = membershipId,
            TenantId = tenantId,
            UserId = userId,
            // Default member role: SSO federates a directory user IN; role elevation
            // is a separate tenant-admin act (SCIM group mapping is a grow-into).
            Role = MembershipRole.Member,
            Status = MembershipStatus.Active,
            InvitedBy = null,
            CreatedAt = now,
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // A concurrent provision beat us to it (the unique (tenant_id, user_id)
            // index). Benign: the membership exists, so dispose rolls this attempt
            // back and the caller proceeds.
            return;
        }

        await outbox.EnqueueAsync(
            db,
            TenancyEvents.MembershipCreated(membershipId, tenantId, userId, MembershipRole.Member, now),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
