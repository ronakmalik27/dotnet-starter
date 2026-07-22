using Microsoft.EntityFrameworkCore;
using Npgsql;
using NpgsqlTypes;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The tenant feature-flag override control plane (feature-flags.md section 5), all
/// operating on the ACTIVE tenant on the REQUEST path under row-level security -
/// never the bypass path. It reads the no-RLS <c>platform.feature_flags</c> catalogue
/// to check <c>tenant_overridable</c>, then writes <c>platform.feature_flag_overrides</c>
/// (RLS) for the active tenant, stamps its domain event through the
/// <see cref="OutboxWriter"/>, and commits once. The endpoint's
/// <c>RequirePermission(feature-flags:manage)</c> gate runs before this.
/// </summary>
internal sealed class FeatureFlagAdminService(
    PlatformDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    IFeatureFlagEvaluator evaluator,
    Clock clock) : IFeatureFlagAdmin
{
    private static readonly Error FlagNotFound = new(
        ErrorKind.NotFound, "tenancy.feature_flag_not_found", "No such feature flag.");

    private static readonly Error NotOverridable = new(
        // Kind is nominal; the Api maps this code to a dedicated 403 (a tenant cannot
        // touch an operator-held flag). It never reaches the generic ErrorKind table.
        ErrorKind.Validation,
        "tenancy.flag_not_overridable",
        "The operator holds this flag centrally; a tenant cannot override it.");

    public async Task<IReadOnlyList<ResolvedFeatureFlag>> ListResolvedAsync(
        Guid? workspaceId, CancellationToken cancellationToken)
    {
        // The resolved value per flag (RLS-bound override read), plus the description
        // and overridable flag from the no-RLS catalogue. Archived flags are hidden
        // from the tenant surface (EvaluateAllAsync skips them). A workspaceId sharpens
        // resolution (a workspace override wins over a tenant override).
        var resolved = await evaluator.EvaluateAllAsync(workspaceId, cancellationToken);

        var catalogue = await db.FeatureFlags
            .AsNoTracking()
            .Where(row => row.ArchivedAt == null)
            .Select(row => new { row.Key, row.Description, row.TenantOverridable })
            .OrderBy(row => row.Key)
            .ToListAsync(cancellationToken);

        return catalogue
            .Select(row => new ResolvedFeatureFlag(
                row.Key,
                row.Description,
                resolved.TryGetValue(row.Key, out var enabled) && enabled,
                row.TenantOverridable))
            .ToList();
    }

    public async Task<Result> SetOverrideAsync(
        Guid callerUserId,
        string flagKey,
        bool enabled,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken)
    {
        if (Normalize(flagKey, scopeType, ref scopeId) is { } validation)
        {
            return Result.Failure(validation);
        }

        flagKey = flagKey.Trim();
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        if (await CheckOverridableAsync(flagKey, cancellationToken) is { } refusal)
        {
            return Result.Failure(refusal);
        }

        // PUT-as-upsert on the NULLS NOT DISTINCT unique index, so a tenant-scope
        // override (scope_id NULL) is unique per flag and a repeat set updates in
        // place. The tenant_id is stamped from the context; RLS's WITH CHECK rejects
        // any write that disagrees with the GUC. The scope_id is an explicitly-typed
        // uuid parameter so a NULL binds as a uuid NULL, not an untyped null.
        var parameters = new object[]
        {
            new NpgsqlParameter("id", NpgsqlDbType.Uuid) { Value = Ids.NewId(now) },
            new NpgsqlParameter("tenant", NpgsqlDbType.Uuid) { Value = tenant.TenantId },
            new NpgsqlParameter("flag", NpgsqlDbType.Text) { Value = flagKey },
            new NpgsqlParameter("scope_type", NpgsqlDbType.Text) { Value = scopeType },
            new NpgsqlParameter("scope_id", NpgsqlDbType.Uuid) { Value = (object?)scopeId ?? DBNull.Value },
            new NpgsqlParameter("enabled", NpgsqlDbType.Boolean) { Value = enabled },
            new NpgsqlParameter("set_by", NpgsqlDbType.Uuid) { Value = callerUserId },
            new NpgsqlParameter("now", NpgsqlDbType.TimestampTz) { Value = now },
        };
        await db.Database.ExecuteSqlRawAsync(
            "insert into platform.feature_flag_overrides "
            + "(id, tenant_id, flag_key, scope_type, scope_id, enabled, set_by, updated_at) "
            + "values (@id, @tenant, @flag, @scope_type, @scope_id, @enabled, @set_by, @now) "
            + "on conflict (tenant_id, flag_key, scope_type, scope_id) do update set "
            + "enabled = excluded.enabled, set_by = excluded.set_by, updated_at = excluded.updated_at",
            parameters,
            cancellationToken);

        await outbox.EnqueueAsync(
            db, FeatureFlagEvents.OverrideSet(flagKey, scopeType, scopeId, enabled, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> ClearOverrideAsync(
        Guid callerUserId,
        string flagKey,
        string scopeType,
        Guid? scopeId,
        CancellationToken cancellationToken)
    {
        if (Normalize(flagKey, scopeType, ref scopeId) is { } validation)
        {
            return Result.Failure(validation);
        }

        flagKey = flagKey.Trim();
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        if (await CheckOverridableAsync(flagKey, cancellationToken) is { } refusal)
        {
            return Result.Failure(refusal);
        }

        // EF's default null-aware comparison renders scope_id == null as IS NULL, so
        // this matches a tenant-scope override too. RLS scopes the delete to the
        // active tenant.
        var removed = await db.FeatureFlagOverrides
            .Where(row => row.FlagKey == flagKey && row.ScopeType == scopeType && row.ScopeId == scopeId)
            .ExecuteDeleteAsync(cancellationToken);

        // Idempotent: clearing an absent override is a benign success with no event.
        if (removed > 0)
        {
            await outbox.EnqueueAsync(
                db, FeatureFlagEvents.OverrideCleared(flagKey, scopeType, scopeId, callerUserId, now), cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    // Reads the no-RLS catalogue row for the flag and returns the refusal error, or
    // null when the flag exists, is not archived, and is tenant-overridable.
    private async Task<Error?> CheckOverridableAsync(string flagKey, CancellationToken cancellationToken)
    {
        var flag = await db.FeatureFlags
            .AsNoTracking()
            .Where(row => row.Key == flagKey)
            .Select(row => new { row.TenantOverridable, row.ArchivedAt })
            .SingleOrDefaultAsync(cancellationToken);
        if (flag is null || flag.ArchivedAt is not null)
        {
            return FlagNotFound;
        }

        return flag.TenantOverridable ? null : NotOverridable;
    }

    private static Error? Normalize(string flagKey, string scopeType, ref Guid? scopeId)
    {
        ArgumentNullException.ThrowIfNull(flagKey);
        ArgumentNullException.ThrowIfNull(scopeType);

        if (flagKey.Trim().Length == 0)
        {
            return new Error(ErrorKind.Validation, "tenancy.flag_key_required", "A flag key is required.");
        }

        if (!FeatureFlagScopes.IsKnown(scopeType))
        {
            return new Error(
                ErrorKind.Validation, "tenancy.flag_scope_invalid", "A scope must be tenant or workspace.");
        }

        if (scopeType == FeatureFlagScopes.Tenant)
        {
            // A tenant-scope override carries no workspace id.
            scopeId = null;
            return null;
        }

        // A workspace-scope override must name the workspace.
        return scopeId is null
            ? new Error(
                ErrorKind.Validation,
                "tenancy.flag_scope_workspace_required",
                "A workspace-scope override requires a workspaceId.")
            : null;
    }
}
