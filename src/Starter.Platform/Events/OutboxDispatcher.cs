using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Events;

/// <summary>
/// The two-lane outbox dispatcher. One leader runs across
/// multiple instances via a Postgres advisory lock; each lane drains on its own
/// cursor so a stalled slow-lane provider never head-of-line-blocks fast
/// dispatch. Claim-commit-send-mark: the claim transaction
/// durably arms an initial lease for every claimed row, and immediately
/// before each send the row's lease is re-armed on the leadership session
/// itself: the re-arm succeeding there proves the lock was held
/// when the lease became durable, so a row whose send may still be in
/// flight can never be re-claimed by a failed-over leader. A re-arm
/// failure means leadership is gone; the batch remainder aborts unsent.
/// Sends run outside any transaction. A crash between send and mark
/// leaves delivered_at null, so the row redelivers after its lease
/// elapses: at-least-once, consumers dedupe by event id.
/// </summary>
public sealed class OutboxDispatcher : BackgroundService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly OutboxOptions _options;
    private readonly OutboxMetrics _metrics;
    private readonly TimeProvider _timeProvider;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<OutboxDispatcher> _logger;
    private readonly Dictionary<Lane, Dictionary<string, IDomainEventConsumer[]>> _consumers;

    public OutboxDispatcher(
        NpgsqlDataSource dataSource,
        IOptions<OutboxOptions> options,
        IEnumerable<IDomainEventConsumer> consumers,
        OutboxMetrics metrics,
        TimeProvider timeProvider,
        IServiceScopeFactory scopeFactory,
        ILogger<OutboxDispatcher> logger)
    {
        _dataSource = dataSource;
        _options = options.Value;
        _metrics = metrics;
        _timeProvider = timeProvider;
        _scopeFactory = scopeFactory;
        _logger = logger;
        _consumers = consumers
            .SelectMany(c => c.EventTypes.Select(t => (Type: t, Consumer: c)))
            .GroupBy(x => x.Consumer.Lane)
            .ToDictionary(
                g => g.Key,
                g => g.GroupBy(x => x.Type, StringComparer.Ordinal)
                    .ToDictionary(
                        tg => tg.Key,
                        tg => tg.Select(x => x.Consumer).Distinct().ToArray(),
                        StringComparer.Ordinal));
    }

    /// <summary>
    /// Test seam (integration suite only): runs after a successful send and
    /// before the delivered_at mark, so the kill-between-send-and-mark case
    /// is exactly reproducible.
    /// </summary>
    internal Func<Guid, Lane, Task>? BetweenSendAndMarkHook { get; set; }

    /// <summary>Observability for the integration suite: true while this instance leads.</summary>
    internal bool IsLeaderForTests { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await using var leadership = new AdvisoryLock(_dataSource, _options.AdvisoryLockKey);
            try
            {
                if (!await leadership.TryAcquireAsync(stoppingToken))
                {
                    await Task.Delay(_options.LeaderRetryInterval, stoppingToken);
                    continue;
                }

                OutboxLog.LeadershipAcquired(_logger);
                IsLeaderForTests = true;
                try
                {
                    await RunLanesAsync(leadership, stoppingToken);
                }
                finally
                {
                    IsLeaderForTests = false;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // SIGTERM: stop claiming; the await-using releases
                // the advisory lock before the host finishes shutdown, so
                // the new deployment's dispatcher can take over immediately.
                return;
            }
            catch (Exception exception)
            {
                OutboxLog.LeadershipLost(_logger, exception);
                if (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    await Task.Delay(_options.LeaderRetryInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private async Task RunLanesAsync(AdvisoryLock leadership, CancellationToken stoppingToken)
    {
        // A lane that detects lock loss cancels its sibling: a new leader
        // owns the queue and this instance must stop claiming everywhere.
        using var lockLost = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);

        await Task.WhenAll(
            RunLaneAsync(Lane.Fast, leadership, lockLost),
            RunLaneAsync(Lane.Slow, leadership, lockLost));
    }

    private async Task RunLaneAsync(
        Lane lane,
        AdvisoryLock leadership,
        CancellationTokenSource lockLost)
    {
        using var timer = new PeriodicTimer(_options.PollInterval(lane));
        try
        {
            while (await timer.WaitForNextTickAsync(lockLost.Token))
            {
                // Re-check the lock between batches: abort on loss.
                if (!await leadership.StillHeldAsync(lockLost.Token))
                {
                    await lockLost.CancelAsync();
                    throw new InvalidOperationException("Advisory lock lost; a new leader owns the queue.");
                }

                List<ClaimedRow> batch;
                try
                {
                    batch = await ClaimBatchAsync(lane, lockLost.Token);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    // A transient claim failure is not lock loss: log, skip
                    // the tick, and let the leadership re-check decide.
                    OutboxLog.TickFailed(_logger, exception, LaneName(lane));
                    continue;
                }

                foreach (var claimed in batch)
                {
                    var lease = await RearmLeaseAsync(lane, claimed, leadership, lockLost.Token);
                    if (lease == LeaseOutcome.LockLost)
                    {
                        // The lease could not be armed on the leadership
                        // session: a new leader owns the queue. Abort the
                        // batch remainder unsent.
                        await lockLost.CancelAsync();
                        throw new InvalidOperationException("Advisory lock lost mid-batch; a new leader owns the queue.");
                    }

                    if (lease == LeaseOutcome.RowUnavailable)
                    {
                        continue;
                    }

                    await SendAsync(lane, claimed, lockLost.Token);
                }
            }
        }
        catch (OperationCanceledException) when (lockLost.IsCancellationRequested)
        {
            // Sibling lane lost the lock, or the host is stopping.
        }
        finally
        {
            // Any exit - deliberate throw, cancellation, or an unforeseen
            // exception - must take the sibling lane down too: a one-lane
            // dispatcher is a half-dead leader nobody re-elects.
            if (!lockLost.IsCancellationRequested)
            {
                await lockLost.CancelAsync();
            }
        }
    }

    private async Task<List<ClaimedRow>> ClaimBatchAsync(
        Lane lane,
        CancellationToken cancellationToken)
    {
        var laneName = LaneName(lane);
        var claimed = new List<ClaimedRow>();

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        // Claim under FOR UPDATE SKIP LOCKED; the joined domain event makes
        // the "load domain_event" step part of the same round trip.
        const string claimSql = """
            select o.event_id, o.attempts, o.enqueued_at,
                   d.occurred_at, d.module, d.event_type, d.entity_id,
                   d.actor_user_id, d.payload, d.tenant_id
            from platform.outbox o
            join platform.domain_events d on d.id = o.event_id
            where o.lane = $1 and o.delivered_at is null
              and o.poisoned_at is null and o.next_attempt_at <= now()
            order by o.enqueued_at
            for update of o skip locked
            limit $2
            """;

        var rows = new List<(Guid EventId, int Attempts, DateTimeOffset EnqueuedAt, DomainEventRecord Evt)>();
        await using (var claim = new NpgsqlCommand(claimSql, connection, transaction)
        {
            Parameters = { new() { Value = laneName }, new() { Value = _options.BatchSize } },
        })
        await using (var reader = await claim.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var eventId = reader.GetGuid(0);
                rows.Add((
                    eventId,
                    reader.GetInt32(1),
                    reader.GetFieldValue<DateTimeOffset>(2),
                    new DomainEventRecord
                    {
                        Id = eventId,
                        OccurredAt = reader.GetFieldValue<DateTimeOffset>(3),
                        Module = reader.GetString(4),
                        EventType = reader.GetString(5),
                        EntityId = reader.GetGuid(6),
                        ActorUserId = reader.IsDBNull(7) ? null : reader.GetGuid(7),
                        Payload = reader.GetString(8),
                        TenantId = reader.IsDBNull(9) ? null : reader.GetGuid(9),
                    }));
            }
        }

        foreach (var row in rows)
        {
            if (row.Attempts >= _options.MaxAttempts)
            {
                // Poison parking: attempts would exceed the cap;
                // park the row (delivered_at stays null) for the replay tool.
                await using var poison = new NpgsqlCommand(
                    "update platform.outbox set attempts = attempts + 1, poisoned_at = now() where event_id = $1 and lane = $2",
                    connection, transaction)
                {
                    Parameters = { new() { Value = row.EventId }, new() { Value = laneName } },
                };
                await poison.ExecuteNonQueryAsync(cancellationToken);
                _metrics.Poisoned(lane);
                OutboxLog.Poisoned(_logger, row.EventId, laneName, row.Attempts, row.Evt.EventType);
                continue;
            }

            // The initial lease, durable inside the claim transaction: it
            // covers a leader that dies right after claiming. The lease
            // that guards each row's actual send window is re-armed per
            // row in RearmLeaseAsync.
            var lease = BackoffPolicy.Lease(_options, lane, row.Attempts, Random.Shared.NextDouble());
            await using var arm = new NpgsqlCommand(
                "update platform.outbox set attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => $3) where event_id = $1 and lane = $2",
                connection, transaction)
            {
                Parameters =
                {
                    new() { Value = row.EventId },
                    new() { Value = laneName },
                    new() { Value = lease.TotalSeconds },
                },
            };
            await arm.ExecuteNonQueryAsync(cancellationToken);
            claimed.Add(new ClaimedRow(row.Evt, row.Attempts, row.EnqueuedAt));
        }

        await transaction.CommitAsync(cancellationToken);
        return claimed;
    }

    /// <summary>
    /// Re-arms the row's lease immediately before its send, on the
    /// advisory lock's own session: success proves the lock was
    /// held when the lease became durable, so the send window that
    /// follows can never overlap a re-claim by a failed-over leader. The
    /// claim-time lease only covers a batch's early rows; this per-row
    /// re-arm is what covers a row that reaches the front after minutes
    /// of sequential draining, and it doubles as the per-row leadership
    /// check that bounds mid-batch loss to the single in-flight send.
    /// </summary>
    private async Task<LeaseOutcome> RearmLeaseAsync(
        Lane lane,
        ClaimedRow claimed,
        AdvisoryLock leadership,
        CancellationToken cancellationToken)
    {
        var lease = BackoffPolicy.Lease(_options, lane, claimed.AttemptsBeforeClaim, Random.Shared.NextDouble());
        var updated = 0;
        var held = await leadership.TryRunOnLockSessionAsync(
            async (connection, token) =>
            {
                await using var rearm = new NpgsqlCommand(
                    "update platform.outbox set next_attempt_at = now() + make_interval(secs => $3) where event_id = $1 and lane = $2 and delivered_at is null and poisoned_at is null",
                    connection)
                {
                    Parameters =
                    {
                        new() { Value = claimed.Event.Id },
                        new() { Value = LaneName(lane) },
                        new() { Value = lease.TotalSeconds },
                    },
                };
                updated = await rearm.ExecuteNonQueryAsync(token);
            },
            cancellationToken);

        if (!held)
        {
            return LeaseOutcome.LockLost;
        }

        if (updated != 1)
        {
            // The row vanished from under a held lock (delivered,
            // poisoned, or purged meanwhile) - unreachable through the
            // dispatcher's own paths. Never send a row the guard refused.
            OutboxLog.LeaseRowUnavailable(_logger, claimed.Event.Id, LaneName(lane));
            return LeaseOutcome.RowUnavailable;
        }

        return LeaseOutcome.Armed;
    }

    private async Task SendAsync(
        Lane lane,
        ClaimedRow claimed,
        CancellationToken cancellationToken)
    {
        var (domainEvent, _, enqueuedAt) = claimed;
        if (!_consumers.TryGetValue(lane, out var byType)
            || !byType.TryGetValue(domainEvent.EventType, out var consumers))
        {
            // Consumer-registration skew: the row was enqueued
            // when this (lane, event_type) had a consumer, but this
            // deployment's registry no longer routes it (removed, renamed,
            // or re-laned during a deploy overlap). Treat it exactly like
            // a failed send - never mark it delivered: the pre-send
            // re-arm already set the retry backoff, so the row redelivers
            // when its lease elapses and poisons at MaxAttempts like any
            // other persistent failure (no lost
            // updates, no ghost events).
            _metrics.Unroutable(lane);
            OutboxLog.Unroutable(_logger, domainEvent.Id, LaneName(lane), domainEvent.EventType);
            return;
        }

        try
        {
            // The send timeout bounds the whole lane send (the
            // pre-send re-arm anchored the lease at this send, so no
            // re-claim races it).
            using var sendWindow = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sendWindow.CancelAfter(_options.SendTimeout(lane));

            // One scope per event, tenant bound from the event's tenant_id
            // BEFORE any consumer runs: the same transaction interceptor then
            // sets the RLS GUC, so a tenant-scoped consumer (and its dedup
            // claim) is bound exactly like an HTTP request, and a consumer that
            // forgets to filter still cannot cross tenants. A platform event
            // (null tenant) leaves the scope unresolved.
            await using var scope = _scopeFactory.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().BindConsumerTenant(domainEvent.TenantId);
            foreach (var consumer in consumers)
            {
                await consumer.ConsumeAsync(scope.ServiceProvider, domainEvent, sendWindow.Token);
            }

            if (BetweenSendAndMarkHook is { } hook)
            {
                await hook(domainEvent.Id, lane);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            // Nothing to do here: the pre-send re-arm already set the
            // retry backoff; the row redelivers when its lease elapses.
            _metrics.SendFailed(lane);
            OutboxLog.SendFailed(_logger, exception, domainEvent.Id, LaneName(lane), domainEvent.EventType);
            return;
        }

        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
            await using var mark = new NpgsqlCommand(
                "update platform.outbox set delivered_at = now() where event_id = $1 and lane = $2 and delivered_at is null and poisoned_at is null",
                connection)
            {
                Parameters = { new() { Value = domainEvent.Id }, new() { Value = LaneName(lane) } },
            };
            var marked = await mark.ExecuteNonQueryAsync(cancellationToken);
            if (marked == 0)
            {
                // A failed-over leader touched the row after this send
                // started: poisoned it (never stamp delivered_at over
                // poisoned_at - a both-set row would be excluded from
                // dispatch AND from the purge forever, violating the
                // parked-row invariant), already marked it
                // delivered (a stale re-mark would shift the timestamp and
                // double-count the dispatch metric), or the purge removed
                // it. The send itself happened; at-least-once already owns
                // that duplicate window, and the replay tool redelivers
                // parked rows deliberately.
                OutboxLog.MarkSuppressed(_logger, domainEvent.Id, LaneName(lane));
                return;
            }

            _metrics.Dispatched(lane, _timeProvider.GetUtcNow() - enqueuedAt);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            // The send succeeded but the mark did not: same redelivery
            // semantics as a crash between send and mark, distinct signal.
            OutboxLog.MarkFailed(_logger, exception, domainEvent.Id, LaneName(lane));
        }
    }

    internal static string LaneName(Lane lane) => LaneNames.Of(lane);

    /// <summary>A claim-transaction row: the event, its attempt count as read under the claim's row lock (pre-increment; the lease formula's input), and its enqueue time (dispatch-lag metric).</summary>
    private readonly record struct ClaimedRow(DomainEventRecord Event, int AttemptsBeforeClaim, DateTimeOffset EnqueuedAt);

    private enum LeaseOutcome
    {
        Armed,
        RowUnavailable,
        LockLost,
    }
}
