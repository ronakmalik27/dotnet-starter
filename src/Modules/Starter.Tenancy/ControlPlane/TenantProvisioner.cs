using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Tenancy.Rbac;
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
    CustomRoleService customRoles,
    Clock clock,
    ILogger<TenantProvisioner> logger)
{
    // The fallback default plan when no is_default row exists in platform.plans
    // (billing-and-entitlements.md section 2): a self-serve tenant starts small.
    // The migration seeds a `free` default, so this fallback only fires if the
    // catalogue was emptied out of band.
    private const int FallbackSeatLimit = 5;

    private const string FallbackPlan = "free";

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

        if (!TenantSlugs.IsValid(slug))
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
            // The is_default plan drives provisioning (billing-and-entitlements.md
            // section 2): a new tenant lands on whatever plan the operator marked
            // default, with that plan's seatLimit. Read it on the bypass connection
            // (platform.plans is off the request role's reach) before opening the
            // provisioning transaction; a plain SELECT auto-commits. Falls back to
            // free / 5 only if no default row exists (an emptied catalogue).
            var (defaultPlan, defaultSeatLimit) = await ReadDefaultPlanAsync(connection, cancellationToken);

            // The active role templates the new tenant is seeded from
            // (role-templates-and-policy-defaults.md section 2). Read on the bypass
            // connection (platform.role_templates is off the request role's reach), a
            // plain SELECT that auto-commits, before the provisioning transaction opens.
            var templates = await ReadActiveTemplatesAsync(connection, cancellationToken);

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
                Plan = defaultPlan,
                SeatLimit = defaultSeatLimit,
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

            // Seed one tenant custom role per active role template
            // (role-templates-and-policy-defaults.md section 2), INSIDE this same
            // provisioning transaction (atomic with the user+tenant+membership commit
            // - a cheap local write, no external I/O). Each insert goes through the
            // custom-role helper on THIS open transaction (never CreateRoleAsync,
            // which would begin a second transaction and throw), filtering the
            // template's permissions to the plan-allowed subset (skip disallowed,
            // never escalate past the plan) and stamping template_key so a later
            // re-seed is idempotent. An empty seeded role is still created. On a
            // brand-new tenant there is no pre-existing role to clash with, so any
            // failure here is a genuine error and rolls the whole provision back -
            // "a failure leaves neither a user nor a tenant".
            foreach (var template in templates)
            {
                var seeded = await customRoles.InsertRoleOnOpenTransactionAsync(
                    db,
                    newTenantId,
                    newUserId,
                    template.Key,
                    template.Name,
                    template.Description,
                    RoleAssignableAt.FromScopes(template.AssignableScopes),
                    workspaceId: null,
                    templateKey: template.Key,
                    template.Permissions,
                    skipDisallowedByPlan: true,
                    now,
                    cancellationToken);
                if (seeded.IsFailure)
                {
                    return Result.Failure<SelfServeSignup>(seeded.Error);
                }
            }

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

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    /// <summary>
    /// Reads the is_default plan's key and seatLimit from platform.plans on the
    /// bypass connection (billing-and-entitlements.md section 2). Falls back to
    /// <see cref="FallbackPlan"/> / <see cref="FallbackSeatLimit"/> when no default
    /// row exists or its limits omit a positive seatLimit, so provisioning always
    /// lands a usable seat limit.
    /// </summary>
    /// <summary>
    /// Reads every role template from platform.role_templates on the bypass
    /// connection (role-templates-and-policy-defaults.md section 2), so a new tenant
    /// is seeded one custom role per template. There is no active/archived state, so
    /// every catalogue row is seeded.
    /// </summary>
    private static async Task<IReadOnlyList<RoleTemplateSeed>> ReadActiveTemplatesAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select key, name, description, permissions, assignable_scopes "
            + "from platform.role_templates order by created_at, key",
            connection);

        var templates = new List<RoleTemplateSeed>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            templates.Add(new RoleTemplateSeed(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetFieldValue<string[]>(3),
                reader.GetFieldValue<string[]>(4)));
        }

        return templates;
    }

    private static async Task<(string Plan, int SeatLimit)> ReadDefaultPlanAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select key, limits from platform.plans where is_default limit 1", connection);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return (FallbackPlan, FallbackSeatLimit);
        }

        var key = reader.GetString(0);
        var limits = reader.GetFieldValue<string>(1);
        var seatLimit = ReadSeatLimit(limits) ?? FallbackSeatLimit;
        return (key, seatLimit);
    }

    private static int? ReadSeatLimit(string limits)
    {
        if (string.IsNullOrWhiteSpace(limits))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(limits);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("seatLimit", out var seatLimit)
                && seatLimit.ValueKind == JsonValueKind.Number
                && seatLimit.TryGetInt32(out var value)
                && value > 0)
            {
                return value;
            }
        }
        catch (JsonException)
        {
            // A malformed limits blob (should never happen; create/update validate
            // it) falls back to the default seat limit rather than throwing at
            // signup.
        }

        return null;
    }
}
