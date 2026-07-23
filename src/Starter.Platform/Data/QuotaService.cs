using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using NpgsqlTypes;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The default <see cref="IQuotaService"/> (quotas.md section 4): the metered-quota
/// counter mechanics over <c>platform.usage_counters</c> through the request-scoped
/// <see cref="PlatformDbContext"/>. Each operation opens ONE transaction, so the
/// tenant interceptor sets the current-tenant GUC and every read and write runs
/// under row-level security for the active tenant, exactly like the feature-flag
/// evaluator and entitlement source. Request-scoped and never touches the bypass
/// data source.
/// </summary>
internal sealed class QuotaService(PlatformDbContext db, ITenantContext tenant, Clock clock) : IQuotaService
{
    public async Task<QuotaOutcome> TryConsumeAsync(
        string metric, long amount, int? limit, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(metric);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);

        var now = clock.UtcNow;
        var resetAt = QuotaPeriod.ResetAt(now);

        // Fail open: an unlimited metric has nothing to enforce, so this is a true
        // no-op - it writes NOTHING (no counter row) and reports zero usage. Metering
        // WHILE unlimited (to drive overage billing) is soft mode (section 9), not
        // this hard gate.
        if (limit is null)
        {
            return new QuotaOutcome(Allowed: true, Used: 0, Limit: null, resetAt);
        }

        var period = QuotaPeriod.PeriodStart(now);

        // One transaction so the interceptor sets the tenant GUC and the reserve runs
        // under RLS. RLS's WITH CHECK rejects any cross-tenant write.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        var dbTransaction = (NpgsqlTransaction)transaction.GetDbTransaction();

        // 1. Ensure the current period's row exists (idempotent). tenant_id is stamped
        //    from the context, never from client input.
        await using (var ensure = new NpgsqlCommand(
            """
            insert into platform.usage_counters (tenant_id, metric, period_start, used, updated_at)
            values (@tenant, @metric, @period, 0, @now)
            on conflict (tenant_id, metric, period_start) do nothing
            """,
            connection,
            dbTransaction))
        {
            ensure.Parameters.Add(new NpgsqlParameter("tenant", NpgsqlDbType.Uuid) { Value = tenant.TenantId });
            ensure.Parameters.Add(new NpgsqlParameter("metric", NpgsqlDbType.Text) { Value = metric });
            ensure.Parameters.Add(new NpgsqlParameter("period", NpgsqlDbType.Date) { Value = period });
            ensure.Parameters.Add(new NpgsqlParameter("now", NpgsqlDbType.TimestampTz) { Value = now });
            await ensure.ExecuteNonQueryAsync(cancellationToken);
        }

        // 2. Guarded reserve: the UPDATE takes a row lock, so concurrent requests
        //    serialize on it - atomic, no check-then-act race, cannot oversell. It
        //    returns the new used when the amount fit under the limit, or zero rows
        //    when the guard blocked the write.
        long? reserved;
        await using (var reserve = new NpgsqlCommand(
            """
            update platform.usage_counters
               set used = used + @amount, updated_at = @now
             where tenant_id = @tenant and metric = @metric and period_start = @period
               and used + @amount <= @limit
            returning used
            """,
            connection,
            dbTransaction))
        {
            reserve.Parameters.Add(new NpgsqlParameter("amount", NpgsqlDbType.Bigint) { Value = amount });
            reserve.Parameters.Add(new NpgsqlParameter("now", NpgsqlDbType.TimestampTz) { Value = now });
            reserve.Parameters.Add(new NpgsqlParameter("tenant", NpgsqlDbType.Uuid) { Value = tenant.TenantId });
            reserve.Parameters.Add(new NpgsqlParameter("metric", NpgsqlDbType.Text) { Value = metric });
            reserve.Parameters.Add(new NpgsqlParameter("period", NpgsqlDbType.Date) { Value = period });
            reserve.Parameters.Add(new NpgsqlParameter("limit", NpgsqlDbType.Bigint) { Value = (long)limit.Value });
            reserved = await reserve.ExecuteScalarAsync(cancellationToken) as long?;
        }

        if (reserved is long consumed)
        {
            await transaction.CommitAsync(cancellationToken);
            return new QuotaOutcome(Allowed: true, consumed, limit, resetAt);
        }

        // Denied: the guard blocked the write, so nothing was consumed. Re-read the
        // current value (unchanged) for the outcome.
        var current = await ReadUsedAsync(connection, dbTransaction, metric, period, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new QuotaOutcome(Allowed: false, current, limit, resetAt);
    }

    public async Task<IReadOnlyList<MeteredUsage>> GetUsageAsync(
        IReadOnlyCollection<string> metrics, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(metrics);

        var wanted = metrics.Distinct(StringComparer.Ordinal).ToArray();
        if (wanted.Length == 0)
        {
            return [];
        }

        var period = QuotaPeriod.PeriodStart(clock.UtcNow);

        // One read transaction so the tenant GUC is set for the RLS-scoped read.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.UsageCounters
            .AsNoTracking()
            .Where(row => row.PeriodStart == period && wanted.Contains(row.Metric))
            .Select(row => new { row.Metric, row.Used })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        var used = rows.ToDictionary(row => row.Metric, row => row.Used, StringComparer.Ordinal);
        return wanted
            .Select(metric => new MeteredUsage(metric, used.TryGetValue(metric, out var value) ? value : 0))
            .ToList();
    }

    private static async Task<long> ReadUsedAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string metric,
        DateOnly period,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            select used from platform.usage_counters
            where metric = @metric and period_start = @period
            """,
            connection,
            transaction);
        command.Parameters.Add(new NpgsqlParameter("metric", NpgsqlDbType.Text) { Value = metric });
        command.Parameters.Add(new NpgsqlParameter("period", NpgsqlDbType.Date) { Value = period });
        return await command.ExecuteScalarAsync(cancellationToken) as long? ?? 0;
    }
}
