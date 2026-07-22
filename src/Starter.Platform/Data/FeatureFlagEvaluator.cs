using Microsoft.EntityFrameworkCore;
using Starter.Platform.Auth;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// The default <see cref="IFeatureFlagEvaluator"/> (feature-flags.md section 3): a
/// per-resolve read of the <c>platform.feature_flags</c> catalogue (no RLS) and the
/// <c>platform.feature_flag_overrides</c> table (RLS) through the request-scoped
/// <see cref="PlatformDbContext"/>. The reads share one transaction, so the tenant
/// interceptor sets the current-tenant GUC and the override read is bound by
/// row-level security to the active tenant - never the bypass source, exactly like
/// the entitlement source.
/// <para>
/// Fail-closed by construction (feature-flags.md section 1): a missing catalogue row
/// (<c>SingleOrDefaultAsync</c> then a null-check) or an archived flag resolves OFF -
/// it never throws and never defaults ON. Resolution is most-specific-wins
/// (workspace override &gt; tenant override &gt; global default/rollout) and is cached
/// per request on <c>(flagKey, workspaceId)</c>.
/// </para>
/// </summary>
internal sealed class FeatureFlagEvaluator(PlatformDbContext db, ITenantContext tenant) : IFeatureFlagEvaluator
{
    private readonly Dictionary<(string FlagKey, Guid? WorkspaceId), bool> _cache = new();

    public async Task<bool> IsEnabledAsync(
        string flagKey, Guid? workspaceId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(flagKey);

        var cacheKey = (flagKey, workspaceId);
        if (_cache.TryGetValue(cacheKey, out var cached))
        {
            return cached;
        }

        // One read transaction so the interceptor sets the tenant GUC for the
        // RLS-scoped override read below (the catalogue read is no-RLS).
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var flag = await db.FeatureFlags
            .AsNoTracking()
            .SingleOrDefaultAsync(row => row.Key == flagKey, cancellationToken);

        bool result;
        if (flag is null || flag.ArchivedAt is not null)
        {
            // Fail closed: an unknown or archived flag is OFF, never ON.
            result = false;
        }
        else
        {
            var overrides = await db.FeatureFlagOverrides
                .AsNoTracking()
                .Where(row => row.FlagKey == flagKey)
                .Select(row => new OverrideValue(row.ScopeType, row.ScopeId, row.Enabled))
                .ToListAsync(cancellationToken);
            result = Resolve(flag, overrides, workspaceId);
        }

        await transaction.CommitAsync(cancellationToken);

        _cache[cacheKey] = result;
        return result;
    }

    public async Task<IReadOnlyDictionary<string, bool>> EvaluateAllAsync(
        Guid? workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var flags = await db.FeatureFlags
            .AsNoTracking()
            .Where(row => row.ArchivedAt == null)
            .ToListAsync(cancellationToken);
        var overrides = await db.FeatureFlagOverrides
            .AsNoTracking()
            .Select(row => new OverrideRow(row.FlagKey, row.ScopeType, row.ScopeId, row.Enabled))
            .ToListAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        var byFlag = overrides
            .GroupBy(row => row.FlagKey, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<OverrideValue>)group
                    .Select(row => new OverrideValue(row.ScopeType, row.ScopeId, row.Enabled))
                    .ToList(),
                StringComparer.Ordinal);

        var resolved = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var flag in flags)
        {
            var flagOverrides = byFlag.TryGetValue(flag.Key, out var list)
                ? list
                : (IReadOnlyList<OverrideValue>)[];
            resolved[flag.Key] = Resolve(flag, flagOverrides, workspaceId);
        }

        return resolved;
    }

    // Most-specific-wins: a workspace override for the active workspace beats a
    // tenant override beats the global default (feature-flags.md section 3).
    private bool Resolve(FeatureFlagRow flag, IReadOnlyList<OverrideValue> overrides, Guid? workspaceId)
    {
        if (workspaceId is Guid workspace)
        {
            foreach (var candidate in overrides)
            {
                if (candidate.ScopeType == FeatureFlagScopes.Workspace && candidate.ScopeId == workspace)
                {
                    return candidate.Enabled;
                }
            }
        }

        foreach (var candidate in overrides)
        {
            if (candidate.ScopeType == FeatureFlagScopes.Tenant)
            {
                return candidate.Enabled;
            }
        }

        // The global default: a deterministic percentage rollout when set, else the
        // fixed default. The bucket is the same for a tenant every time, so a tenant
        // is stably in or out.
        return flag.RolloutPercentage is int percentage
            ? FeatureFlagBucket.Bucket(flag.Key, tenant.TenantId) < percentage
            : flag.DefaultEnabled;
    }

    private readonly record struct OverrideValue(string ScopeType, Guid? ScopeId, bool Enabled);

    private readonly record struct OverrideRow(string FlagKey, string ScopeType, Guid? ScopeId, bool Enabled);
}
