using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Self-serve provisioning: creates a brand-new user, a new tenant, and the
/// caller's owner membership ATOMICALLY in one transaction on the bypass data
/// source, emitting UserRegistered (global), TenantCreated and MembershipCreated
/// (tenant-scoped). This is one of the two Tenancy types the bypass-containment
/// arch test allowlists - crossing tenants to establish a new boundary is
/// exactly what the bypass role is for, since a tenant boundary must be created
/// before any tenant context exists.
/// <para>
/// The atomicity is the enlist-a-second-context-on-one-connection pattern
/// OutboxWriter uses: one connection, one transaction, shared by the Identity
/// staging context, this provisioning context, and the outbox writer's platform
/// context. "A failure leaves neither a user nor a tenant" holds because there
/// is a single commit; any failure disposes without committing and rolls back
/// every write.
/// </para>
/// <para>
/// Enumeration-safety: if the email already belongs to an existing user, the
/// staging seam reports it WITHOUT creating a user, the whole transaction rolls
/// back (no tenant, no membership), and the caller returns the same generic
/// success as a fresh signup with no tokens - a session is never issued for an
/// account whose credentials were not verified. The person simply logs in
/// normally. Nothing leaks whether the email pre-existed.
/// </para>
/// </summary>
internal sealed class TenantProvisioner(
    BypassDataSource bypass,
    ITenantProvisioningIdentity identity,
    OutboxWriter outbox,
    Clock clock,
    ILogger<TenantProvisioner> logger)
{
    private const int MaxSlugLength = 63;

    // A sensible free-tier default: a self-serve tenant starts small and raises
    // its seat limit on a paid plan (out of scope this increment).
    private const int DefaultSeatLimit = 5;

    private const string DefaultPlan = "free";

    public async Task<Result<SelfServeSignup>> ProvisionAsync(
        string email,
        string password,
        string tenantName,
        string slug,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(tenantName);
        ArgumentNullException.ThrowIfNull(slug);

        tenantName = tenantName.Trim();
        slug = slug.Trim();
        if (tenantName.Length == 0)
        {
            return Result.Failure<SelfServeSignup>(new Error(
                ErrorKind.Validation, "tenancy.name_required", "A tenant name is required."));
        }

        if (!IsValidSlug(slug))
        {
            return Result.Failure<SelfServeSignup>(new Error(
                ErrorKind.Validation,
                "tenancy.slug_invalid",
                "A tenant slug must be 1-63 characters of letters, digits, and hyphens."));
        }

        var now = clock.UtcNow;
        var newTenantId = Ids.NewId(now);

        Guid newUserId;
        string rawVerificationToken;

        // One connection and one transaction on the bypass data source: the
        // user, the tenant, and the owner membership all share them, so they
        // commit or roll back together.
        await using (var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken))
        {
            var options = StarterDbContextOptions.ForConnection<TenancyDbContext>(connection).Options;

            // Resolve the provisioning context to the NEW tenant, so OutboxWriter
            // stamps TenantCreated / MembershipCreated with tenant_id =
            // newTenantId. On the BYPASSRLS role the GUC the interceptor sets is
            // harmless and the inserts are not RLS-checked.
            await using var db = new TenancyDbContext(options, ITenantContext.ForTenant(newTenantId));
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

            // Stage the user first, on the SAME connection + transaction. The
            // seam enlists on this transaction (its own IdentityDbContext) and
            // does NOT commit - this provisioner owns the single commit.
            var staged = await identity.StageRegistrationAsync(
                connection, transaction, email, password, cancellationToken);
            if (staged.IsFailure)
            {
                // A bad email or weak password: nothing was staged; dispose rolls back.
                return Result.Failure<SelfServeSignup>(staged.Error);
            }

            if (staged.Value.EmailAlreadyExists)
            {
                // The email already has an account: the seam staged nothing, so
                // dispose rolls back (no tenant, no membership). Same generic
                // success as a fresh signup, but with no tokens.
                return Result.Success(SelfServeSignup.ExistingAccount);
            }

            newUserId = staged.Value.UserId;
            rawVerificationToken = staged.Value.RawVerificationToken!;

            var membershipId = Ids.NewId(now);
            db.Tenants.Add(new Tenant
            {
                Id = newTenantId,
                Slug = slug,
                Name = tenantName,
                Status = TenantStatus.Active,
                Plan = DefaultPlan,
                SeatLimit = DefaultSeatLimit,
                CreatedAt = now,
                CreatedBy = newUserId,
            });
            db.Memberships.Add(new Membership
            {
                Id = membershipId,
                TenantId = newTenantId,
                UserId = newUserId,
                Role = MembershipRole.Owner,
                Status = MembershipStatus.Active,
                InvitedBy = null,
                CreatedAt = now,
            });

            try
            {
                // The tenant + membership INSERT: the slug's citext unique index
                // fires here on a collision.
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException exception) when (IsUniqueViolation(exception))
            {
                // The slug is taken. The whole unit rolls back (dispose), so the
                // staged user AND the tenant are both gone - "a failure leaves
                // neither". A slug is caller-supplied and not a secret, so a 409
                // that confirms it is taken is fine.
                return Result.Failure<SelfServeSignup>(new Error(
                    ErrorKind.Conflict, "tenancy.slug_taken", "That tenant slug is already taken."));
            }

            // Enqueue the tenant-scoped events on the provisioning context
            // (tenant_id = newTenantId), same open transaction.
            await outbox.EnqueueAsync(
                db, TenancyEvents.TenantCreated(newTenantId, newUserId, now), cancellationToken);
            await outbox.EnqueueAsync(
                db,
                TenancyEvents.MembershipCreated(membershipId, newTenantId, newUserId, MembershipRole.Owner, now),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }

        // Post-commit, best-effort and non-fatal: the tenant and owner exist even
        // if either step below fails, and the owner recovers through the normal
        // verify + login flow.
        try
        {
            await identity.SendVerificationEmailAsync(email, rawVerificationToken, cancellationToken);
        }
        catch (Exception exception)
        {
            TenancyLog.VerificationEmailFailed(logger, exception);
        }

        // Auto-login the new owner bound to the new tenant, so the returned
        // access token carries tid = newTenantId. If issuance fails, return the
        // generic tokenless success; the owner logs in and selects the tenant.
        var login = await identity.IssueSessionForAsync(
            newUserId, newTenantId, deviceLabel, ipAddress, cancellationToken);
        if (login.IsFailure)
        {
            TenancyLog.AutoLoginFailed(logger, login.Error.Code);
            return Result.Success(SelfServeSignup.Created(tokens: null));
        }

        return Result.Success(SelfServeSignup.Created(login.Value));
    }

    private static bool IsValidSlug(string slug)
    {
        // Letters (either case; citext makes uniqueness case-insensitive),
        // digits, and hyphens, within the label length ceiling. Deliberately
        // permissive on case so "Acme" and "acme" are both valid inputs that
        // then collide on the citext unique index.
        if (slug.Length is 0 or > MaxSlugLength)
        {
            return false;
        }

        foreach (var character in slug)
        {
            var isAllowed = char.IsAsciiLetterOrDigit(character) || character == '-';
            if (!isAllowed)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
