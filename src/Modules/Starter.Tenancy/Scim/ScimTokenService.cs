using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Scim;

/// <summary>
/// The SCIM-token control plane (sso-and-scim.md section 5), all operating on the
/// ACTIVE tenant on the REQUEST path under row-level security - NOT the bypass path
/// (the resolve is the only cross-tenant step, and it lives in
/// <c>ScimTokenResolver</c>). Every write opens a transaction so the tenant
/// interceptor sets the current-tenant GUC (RLS then binds every read and write to
/// the active tenant), stamps its domain event through the OutboxWriter, and commits
/// once. The endpoint's RequirePermission(settings:manage) gate runs before this.
/// It mirrors <c>ServiceAccountService</c>, minus the RBAC-grant coupling: a SCIM
/// token carries no role - possession of the tid-scoped bearer IS the authority for
/// the SCIM surface.
/// </summary>
internal sealed class ScimTokenService(
    TenancyDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    Clock clock)
{
    public async Task<Result<(Guid Id, string RawToken, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>>
        CreateAsync(Guid callerUserId, DateTimeOffset? expiresAt, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var expiry = expiresAt?.ToUniversalTime();
        var rawToken = ScimTokenSecrets.NewToken();
        var tokenId = Ids.NewId(now);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.ScimTokens.Add(new ScimToken
        {
            Id = tokenId,
            TenantId = tenant.TenantId,
            TokenHash = ScimTokenSecrets.Hash(rawToken),
            TokenPrefix = ScimTokenSecrets.Prefix(rawToken),
            CreatedBy = callerUserId,
            CreatedAt = now,
            ExpiresAt = expiry,
        });
        await db.SaveChangesAsync(cancellationToken);

        // A create reuses the rotated event: both mean "a new SCIM bearer now exists
        // for this tenant" and neither carries the secret (mirrors the empty
        // ServiceAccountRotated payload).
        await outbox.EnqueueAsync(
            db, TenancyEvents.ScimTokenRotated(tokenId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success((tokenId, rawToken, ScimTokenSecrets.Prefix(rawToken), now, expiry));
    }

    public async Task<IReadOnlyList<(Guid Id, string TokenPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt)>>
        ListAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.ScimTokens
            .AsNoTracking()
            .OrderByDescending(token => token.CreatedAt)
            .ThenByDescending(token => token.Id)
            .Select(token => new
            {
                token.Id,
                // The hash is NEVER selected: the list carries only the display prefix.
                token.TokenPrefix,
                token.CreatedAt,
                token.ExpiresAt,
                token.RevokedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.TokenPrefix, row.CreatedAt, row.ExpiresAt, row.RevokedAt))
            .ToList();
    }

    public async Task<Result<(string RawToken, string TokenPrefix)>> RotateAsync(
        Guid callerUserId, Guid tokenId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var rawToken = ScimTokenSecrets.NewToken();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var token = await db.ScimTokens.SingleOrDefaultAsync(
            candidate => candidate.Id == tokenId, cancellationToken);
        if (token is null)
        {
            return Result.Failure<(string, string)>(ScimTokenNotFound);
        }

        // Rotate replaces the hash and prefix on the SAME row, so the old secret stops
        // resolving immediately (one active hash). revoked_at stays null: this row is
        // still the tenant's live token, now carrying a new secret.
        token.TokenHash = ScimTokenSecrets.Hash(rawToken);
        token.TokenPrefix = ScimTokenSecrets.Prefix(rawToken);
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(
            db, TenancyEvents.ScimTokenRotated(tokenId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success((rawToken, token.TokenPrefix));
    }

    public async Task<Result> RevokeAsync(Guid callerUserId, Guid tokenId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var token = await db.ScimTokens.SingleOrDefaultAsync(
            candidate => candidate.Id == tokenId, cancellationToken);
        if (token is null)
        {
            return Result.Failure(ScimTokenNotFound);
        }

        // Idempotent: an already-revoked token is a benign success (its secret already
        // fails to resolve) - directory syncs and admins retry. Un-revoke is not
        // offered; mint a new token.
        if (token.RevokedAt is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return Result.Success();
        }

        token.RevokedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private static readonly Error ScimTokenNotFound = new(
        ErrorKind.NotFound, "tenancy.scim_token_not_found", "No such SCIM token.");
}
