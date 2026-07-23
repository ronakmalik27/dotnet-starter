using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Sso;

/// <summary>
/// The tenant-admin SSO control plane (sso-and-scim.md sections 2, 3), all
/// operating on the ACTIVE tenant on the REQUEST path under row-level security -
/// NOT the bypass path (the cross-tenant reads live in
/// <see cref="Starter.Tenancy.ControlPlane.TenantSsoConfigReader"/>). Every write
/// opens a transaction so the tenant interceptor sets the current-tenant GUC (RLS
/// then binds every read and write to the active tenant), stamps its domain event
/// through the OutboxWriter, and commits once. The endpoint's
/// RequirePermission(settings:manage) gate runs before this.
/// </summary>
internal sealed class SsoConfigService(
    TenancyDbContext db,
    ITenantContext tenant,
    SsoClientSecretProtector secrets,
    OutboxWriter outbox,
    Clock clock)
{
    private const int MaxFieldLength = 2048;

    /// <summary>
    /// Sets (creates or replaces) the tenant's SSO configuration. The issuer MUST
    /// be https - a plain-http issuer weakens the JWKS/discovery fetch to network
    /// tampering, so it is rejected here at save time (sso-and-scim.md section 3);
    /// the loopback test exception stays confined to the test host's IdP metadata,
    /// never this admin endpoint. The client secret is write-only: stored only
    /// DataProtection-encrypted, never read back.
    /// </summary>
    public async Task<Result> SetConfigAsync(
        Guid callerUserId,
        string issuer,
        string clientId,
        string clientSecret,
        bool enabled,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(clientSecret);

        issuer = issuer.Trim();
        clientId = clientId.Trim();

        if (issuer.Length is 0 or > MaxFieldLength
            || !Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri)
            || !string.Equals(issuerUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            // The load-bearing security check: a non-https issuer is refused so the
            // discovery/JWKS fetch cannot be tampered with in transit.
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "tenancy.sso_issuer_insecure",
                "The SSO issuer must be an absolute https URL."));
        }

        if (clientId.Length is 0 or > MaxFieldLength)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.sso_client_id_invalid", "A client id is required."));
        }

        if (clientSecret.Length is 0 or > MaxFieldLength)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.sso_client_secret_invalid", "A client secret is required."));
        }

        var now = clock.UtcNow;
        var encrypted = secrets.Protect(clientSecret);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // At most one config per tenant (PK is tenant_id), scoped to the active
        // tenant under RLS. Upsert: replace the existing row, else create.
        var existing = await db.SsoConfigs.SingleOrDefaultAsync(cancellationToken);
        if (existing is null)
        {
            db.SsoConfigs.Add(new SsoConfig
            {
                TenantId = tenant.TenantId,
                Issuer = issuer,
                ClientId = clientId,
                ClientSecretEncrypted = encrypted,
                Enabled = enabled,
                CreatedAt = now,
                UpdatedAt = now,
            });
        }
        else
        {
            existing.Issuer = issuer;
            existing.ClientId = clientId;
            existing.ClientSecretEncrypted = encrypted;
            existing.Enabled = enabled;
            existing.UpdatedAt = now;
        }

        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.SsoConfigured(tenant.TenantId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    /// <summary>
    /// Claims an email domain for the active tenant's SSO routing (sso-and-scim.md
    /// sections 2, 3). The claim is created UNVERIFIED (<c>verified_at</c> null): it
    /// does not route until an operator approves it (DNS-TXT self-verification is a
    /// documented grow-into). A domain already claimed by ANY tenant is a CONSTRAINT
    /// violation on the global unique index, surfaced as a conflict - the two
    /// controls (global uniqueness + verified-to-route) that defend against a
    /// takeover claim.
    /// </summary>
    public async Task<Result<Guid>> ClaimDomainAsync(
        Guid callerUserId, string domain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        domain = domain.Trim().ToLowerInvariant();
        if (domain.Length is 0 or > 253
            || domain.Contains('@', StringComparison.Ordinal)
            || domain.Contains('/', StringComparison.Ordinal)
            || domain.Any(char.IsWhiteSpace)
            || !domain.Contains('.', StringComparison.Ordinal))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.sso_domain_invalid", "A valid email domain is required."));
        }

        var now = clock.UtcNow;
        var claimId = Ids.NewId(now);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.SsoDomainClaims.Add(new SsoDomainClaim
        {
            Id = claimId,
            TenantId = tenant.TenantId,
            Domain = domain,
            VerifiedAt = null,
            CreatedAt = now,
        });

        try
        {
            // The global unique index on the normalized domain fires here when any
            // tenant (this one or another) already claims it. RLS hides another
            // tenant's row from a read, but the index enforces across the boundary,
            // so a duplicate claim can never silently succeed.
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Conflict,
                "tenancy.sso_domain_claimed",
                "That domain is already claimed."));
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.SsoConfigured(tenant.TenantId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(claimId);
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
