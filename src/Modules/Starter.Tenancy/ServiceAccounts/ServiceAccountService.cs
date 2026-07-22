using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Tenancy.Rbac;
using Starter.Platform.Events;
using Starter.Platform.Paging;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.ServiceAccounts;

/// <summary>
/// The service-account control plane (service-accounts.md sections 5, 7), all
/// operating on the ACTIVE tenant on the REQUEST path under row-level security -
/// NOT the bypass path (the resolve is the only cross-tenant step, and it lives in
/// <c>ApiKeyResolver</c>). Every write opens a transaction so the tenant
/// interceptor sets the current-tenant GUC (RLS then binds every read and write to
/// the active tenant), stamps its domain event through the OutboxWriter, and
/// commits once. The endpoint's RequirePermission(api-keys:manage) gate runs
/// before this.
/// <para>
/// Create optionally grants an initial role in the SAME transaction as the account
/// insert, reusing <see cref="CustomRoleService.AssignRoleCoreAsync"/> so the
/// self-escalation refusal (roles:manage / api-keys:manage never grantable to a
/// service account) is enforced identically to the direct assign path, and a
/// refused grant rolls the whole create back (service-accounts.md section 4). The
/// two services share the request-scoped context, so the core assign participates
/// in this transaction.
/// </para>
/// </summary>
internal sealed class ServiceAccountService(
    TenancyDbContext db,
    ITenantContext tenant,
    CustomRoleService customRoles,
    OutboxWriter outbox,
    Clock clock)
{
    private const int MaxNameLength = 128;

    public async Task<Result<(Guid Id, string RawKey, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>>
        CreateAsync(
            Guid callerUserId,
            string name,
            DateTimeOffset? expiresAt,
            Guid? roleId,
            string? scopeType,
            Guid? scopeId,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        name = name.Trim();
        if (name.Length == 0 || name.Length > MaxNameLength)
        {
            return Failure(new Error(
                ErrorKind.Validation,
                "tenancy.service_account_name_invalid",
                $"A service-account name must be 1-{MaxNameLength} characters."));
        }

        // Normalize and shape-validate the initial-role scope BEFORE any write, so
        // a bad scope fails with nothing created. A role given with no explicit
        // scope defaults to tenant scope.
        var effectiveScopeType = AssignmentScope.Tenant;
        Guid? normalizedScopeId = null;
        if (roleId is not null)
        {
            effectiveScopeType = string.IsNullOrWhiteSpace(scopeType) ? AssignmentScope.Tenant : scopeType;
            if (effectiveScopeType is not (AssignmentScope.Tenant or AssignmentScope.Workspace))
            {
                return Failure(new Error(
                    ErrorKind.Validation, "tenancy.scope_invalid", "scopeType must be tenant or workspace."));
            }

            if (effectiveScopeType == AssignmentScope.Workspace && scopeId is null)
            {
                return Failure(new Error(
                    ErrorKind.Validation, "tenancy.scope_id_required", "A workspace-scope grant requires a scopeId."));
            }

            normalizedScopeId = effectiveScopeType == AssignmentScope.Workspace ? scopeId : null;
        }

        var now = clock.UtcNow;
        var expiry = expiresAt?.ToUniversalTime();
        var rawKey = ApiKeySecrets.NewKey();
        var accountId = Ids.NewId(now);

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.ServiceAccounts.Add(new ServiceAccount
        {
            Id = accountId,
            TenantId = tenant.TenantId,
            Name = name,
            KeyHash = ApiKeySecrets.Hash(rawKey),
            KeyPrefix = ApiKeySecrets.Prefix(rawKey),
            CreatedBy = callerUserId,
            CreatedAt = now,
            ExpiresAt = expiry,
        });
        // Flush so the account row is visible to the assign core's existence read
        // in this same transaction.
        await db.SaveChangesAsync(cancellationToken);

        if (roleId is Guid initialRoleId)
        {
            // Same assign path as a direct grant: it validates the role, the
            // scope, and the NotServiceAccountGrantable refusal, and enqueues the
            // granted event - all in this transaction. A failure returns here and
            // the dispose below rolls the account insert back too (atomic create).
            var assigned = await customRoles.AssignRoleCoreAsync(
                callerUserId,
                initialRoleId,
                PrincipalType.ServiceAccount,
                accountId,
                effectiveScopeType,
                normalizedScopeId,
                now,
                cancellationToken);
            if (assigned.IsFailure)
            {
                return Failure(assigned.Error);
            }
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.ServiceAccountCreated(accountId, name, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success((accountId, rawKey, ApiKeySecrets.Prefix(rawKey), now, expiry));
    }

    public async Task<Result<(IReadOnlyList<(Guid Id, string Name, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt)> Items, string? NextCursor)>>
        ListAsync(int limit, string? cursor, CancellationToken cancellationToken)
    {
        limit = PageLimit.Clamp(limit);

        KeysetCursor? after = null;
        if (!string.IsNullOrEmpty(cursor))
        {
            if (!KeysetCursor.TryDecode(cursor, out var decoded))
            {
                return Result.Failure<(IReadOnlyList<(Guid, string, string, DateTimeOffset, DateTimeOffset?, DateTimeOffset?, DateTimeOffset?)>, string?)>(
                    new Error(ErrorKind.Validation, "tenancy.cursor_malformed", "The pagination cursor is malformed."));
            }

            after = decoded;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var query = db.ServiceAccounts.AsNoTracking();
        if (after is { } key)
        {
            query = query.Where(account =>
                account.CreatedAt < key.CreatedAt
                || (account.CreatedAt == key.CreatedAt && account.Id.CompareTo(key.Id) < 0));
        }

        var rows = await query
            .OrderByDescending(account => account.CreatedAt)
            .ThenByDescending(account => account.Id)
            .Take(limit + 1)
            .Select(account => new
            {
                account.Id,
                account.Name,
                account.KeyPrefix,
                account.CreatedAt,
                account.LastUsedAt,
                account.ExpiresAt,
                account.RevokedAt,
            })
            .ToListAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            var lastKept = rows[limit - 1];
            nextCursor = new KeysetCursor(lastKept.CreatedAt, lastKept.Id).Encode();
            rows.RemoveAt(rows.Count - 1);
        }

        var items = rows
            .Select(row => (
                row.Id, row.Name, row.KeyPrefix, row.CreatedAt, row.LastUsedAt, row.ExpiresAt, row.RevokedAt))
            .ToList();

        return Result.Success<(IReadOnlyList<(Guid, string, string, DateTimeOffset, DateTimeOffset?, DateTimeOffset?, DateTimeOffset?)>, string?)>(
            (items, nextCursor));
    }

    public async Task<Result<(string RawKey, string KeyPrefix)>> RotateAsync(
        Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var rawKey = ApiKeySecrets.NewKey();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var account = await db.ServiceAccounts.SingleOrDefaultAsync(
            candidate => candidate.Id == serviceAccountId, cancellationToken);
        if (account is null)
        {
            return Result.Failure<(string, string)>(ServiceAccountNotFound);
        }

        // One active hash: replacing it stops the old secret immediately.
        account.KeyHash = ApiKeySecrets.Hash(rawKey);
        account.KeyPrefix = ApiKeySecrets.Prefix(rawKey);
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(
            db, TenancyEvents.ServiceAccountRotated(serviceAccountId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success((rawKey, account.KeyPrefix));
    }

    public async Task<Result> RevokeAsync(
        Guid callerUserId, Guid serviceAccountId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var account = await db.ServiceAccounts.SingleOrDefaultAsync(
            candidate => candidate.Id == serviceAccountId, cancellationToken);
        if (account is null)
        {
            return Result.Failure(ServiceAccountNotFound);
        }

        // Idempotent: an already-revoked account is a benign success (its key
        // already fails to resolve). Un-revoke is not offered - mint a new account.
        if (account.RevokedAt is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return Result.Success();
        }

        account.RevokedAt = now;
        await db.SaveChangesAsync(cancellationToken);

        await outbox.EnqueueAsync(
            db, TenancyEvents.ServiceAccountRevoked(serviceAccountId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    private static readonly Error ServiceAccountNotFound = new(
        ErrorKind.NotFound, "tenancy.service_account_not_found", "No such service account.");

    private static Result<(Guid Id, string RawKey, string KeyPrefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)>
        Failure(Error error) =>
        Result.Failure<(Guid, string, string, DateTimeOffset, DateTimeOffset?)>(error);
}
