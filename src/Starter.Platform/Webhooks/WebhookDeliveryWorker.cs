using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The delivery worker (webhooks.md section 4), modelled on <c>OutboxDispatcher</c>: a
/// leader-elected <see cref="BackgroundService"/> that claims pending delivery rows and
/// POSTs each, with per-ROW retry and dead-letter.
/// <list type="bullet">
///   <item><b>Leadership</b> via its own advisory lock with a DISTINCT key (not the
///   outbox's), so exactly one instance delivers.</item>
///   <item><b>Claim</b> on the BYPASS path (the deliveries table is RLS-owned, so a
///   request-role connection sees zero rows without a tenant GUC): <c>for update skip
///   locked</c>, arming a lease in the same transaction so a crashed leader's in-flight
///   rows reclaim only after the lease.</item>
///   <item><b>Per-row re-arm on the lock session</b> immediately before each send (the
///   real double-send anchor): success there proves the lock is still held at send time,
///   so a failed-over leader cannot have already reclaimed the row.</item>
///   <item><b>Send-time endpoint re-check</b>: a deleted-or-disabled endpoint drops the
///   delivery (dead) rather than POSTing.</item>
///   <item><b>Outcome</b>: a 2xx delivers; anything else backs off
///   (<c>min(2^attempts, MaxBackoff) + jitter</c>) and dead-letters at <c>MaxAttempts</c>.
///   A distinct <c>Unprotect</c> failure dead-letters immediately.</item>
/// </list>
/// The signing secret and the receiver URL never appear in a log line.
/// </summary>
public sealed class WebhookDeliveryWorker : BackgroundService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly WebhookOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly WebhookSecretProtector _protector;
    private readonly Clock _clock;
    private readonly ILogger<WebhookDeliveryWorker> _logger;

    public WebhookDeliveryWorker(
        BypassDataSource bypass,
        IOptions<WebhookOptions> options,
        IHttpClientFactory httpClientFactory,
        WebhookSecretProtector protector,
        Clock clock,
        ILogger<WebhookDeliveryWorker> logger)
    {
        ArgumentNullException.ThrowIfNull(bypass);
        ArgumentNullException.ThrowIfNull(options);
        _dataSource = bypass.DataSource;
        _options = options.Value;
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

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

                WebhookLog.LeadershipAcquired(_logger);
                IsLeaderForTests = true;
                try
                {
                    await RunAsync(leadership, stoppingToken);
                }
                finally
                {
                    IsLeaderForTests = false;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // SIGTERM: the await-using releases the advisory lock before shutdown
                // finishes, so a new deployment's worker can take over immediately.
                return;
            }
            catch (Exception exception)
            {
                WebhookLog.LeadershipLost(_logger, exception);
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

    private async Task RunAsync(AdvisoryLock leadership, CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.PollInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            // Re-check the lock between batches: abort on loss so a new leader owns the queue.
            if (!await leadership.StillHeldAsync(stoppingToken))
            {
                throw new InvalidOperationException("Advisory lock lost; a new leader owns the queue.");
            }

            List<ClaimedDelivery> batch;
            try
            {
                batch = await ClaimBatchAsync(stoppingToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // A transient claim failure is not lock loss: log, skip the tick.
                WebhookLog.TickFailed(_logger, exception);
                continue;
            }

            foreach (var claimed in batch)
            {
                var lease = await RearmLeaseAsync(claimed, leadership, stoppingToken);
                if (lease == LeaseOutcome.LockLost)
                {
                    throw new InvalidOperationException("Advisory lock lost mid-batch; a new leader owns the queue.");
                }

                if (lease == LeaseOutcome.RowUnavailable)
                {
                    continue;
                }

                await DeliverAsync(claimed, stoppingToken);
            }
        }
    }

    private async Task<List<ClaimedDelivery>> ClaimBatchAsync(CancellationToken cancellationToken)
    {
        var claimed = new List<ClaimedDelivery>();

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        const string claimSql = """
            select id, endpoint_id, event_type, payload, attempts
            from platform.webhook_deliveries
            where status = 'pending' and next_attempt_at <= now()
            order by next_attempt_at
            for update skip locked
            limit $1
            """;

        var rows = new List<(Guid Id, Guid EndpointId, string EventType, string Payload, int Attempts)>();
        await using (var claim = new NpgsqlCommand(claimSql, connection, transaction)
        {
            Parameters = { new() { Value = _options.BatchSize } },
        })
        await using (var reader = await claim.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                rows.Add((
                    reader.GetGuid(0),
                    reader.GetGuid(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetInt32(4)));
            }
        }

        foreach (var row in rows)
        {
            if (row.Attempts >= _options.MaxAttempts)
            {
                // Defensive dead-letter: a row that somehow re-enters at the cap parks
                // rather than sending (the outcome step is the normal dead-letter path).
                await using var park = new NpgsqlCommand(
                    "update platform.webhook_deliveries set status = 'dead', dead_lettered_at = now(), last_error = 'max attempts exceeded' where id = $1 and status = 'pending'",
                    connection, transaction)
                {
                    Parameters = { new() { Value = row.Id } },
                };
                await park.ExecuteNonQueryAsync(cancellationToken);
                WebhookLog.DeadLettered(_logger, row.Id, row.Attempts, "max attempts exceeded");
                continue;
            }

            // The claim-time lease, durable in this transaction: covers a leader that dies
            // right after claiming. The per-row re-arm before each send is the send-window
            // anchor.
            var lease = ClaimLease(row.Attempts);
            await using var arm = new NpgsqlCommand(
                "update platform.webhook_deliveries set attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => $2) where id = $1",
                connection, transaction)
            {
                Parameters = { new() { Value = row.Id }, new() { Value = lease.TotalSeconds } },
            };
            await arm.ExecuteNonQueryAsync(cancellationToken);
            claimed.Add(new ClaimedDelivery(row.Id, row.EndpointId, row.EventType, row.Payload, row.Attempts));
        }

        await transaction.CommitAsync(cancellationToken);
        return claimed;
    }

    private async Task<LeaseOutcome> RearmLeaseAsync(
        ClaimedDelivery claimed, AdvisoryLock leadership, CancellationToken cancellationToken)
    {
        var lease = ClaimLease(claimed.AttemptsBeforeClaim);
        var updated = 0;
        var held = await leadership.TryRunOnLockSessionAsync(
            async (connection, token) =>
            {
                await using var rearm = new NpgsqlCommand(
                    "update platform.webhook_deliveries set next_attempt_at = now() + make_interval(secs => $2) where id = $1 and status = 'pending'",
                    connection)
                {
                    Parameters = { new() { Value = claimed.Id }, new() { Value = lease.TotalSeconds } },
                };
                updated = await rearm.ExecuteNonQueryAsync(token);
            },
            cancellationToken);

        if (!held)
        {
            return LeaseOutcome.LockLost;
        }

        // The row vanished from under a held lock (delivered, dead, replayed, or deleted
        // meanwhile): never send a row the guard could not re-arm.
        return updated == 1 ? LeaseOutcome.Armed : LeaseOutcome.RowUnavailable;
    }

    private async Task DeliverAsync(ClaimedDelivery claimed, CancellationToken cancellationToken)
    {
        // Send-time endpoint re-check (fan-out only filtered at enqueue): a deleted or
        // disabled endpoint drops the delivery rather than POSTing.
        var endpoint = await LoadEndpointAsync(claimed.EndpointId, cancellationToken);
        if (endpoint is not { } target || target.Disabled)
        {
            await MarkDeadAsync(claimed.Id, responseStatus: null, "endpoint deleted or disabled", cancellationToken);
            WebhookLog.EndpointGone(_logger, claimed.Id);
            return;
        }

        string secret;
        try
        {
            secret = _protector.Unprotect(target.Ciphertext);
        }
        catch (WebhookSecretUnprotectException)
        {
            // A lost or rotated-away key can never succeed: dead-letter immediately rather
            // than burning the whole retry budget (webhooks.md sections 4, 5).
            await MarkDeadAsync(claimed.Id, responseStatus: null, "signing secret unavailable", cancellationToken);
            WebhookLog.SecretUnavailable(_logger, claimed.Id);
            return;
        }

        var timestamp = _clock.UtcNow.ToUnixTimeSeconds();
        var header = WebhookSigner.BuildHeader(secret, timestamp, claimed.Payload);

        int? responseStatus = null;
        string error;
        try
        {
            using var sendWindow = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sendWindow.CancelAfter(_options.SendTimeout);

            var client = _httpClientFactory.CreateClient(WebhookHttpClient.ClientName);
            using var request = new HttpRequestMessage(HttpMethod.Post, target.Url)
            {
                Content = new StringContent(claimed.Payload, Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation(WebhookSigner.HeaderName, header);

            using var response = await client.SendAsync(request, sendWindow.Token);
            responseStatus = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                await MarkDeliveredAsync(claimed.Id, responseStatus.Value, cancellationToken);
                return;
            }

            error = $"http_status_{responseStatus}";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The worker is shutting down: leave the row; its lease redelivers.
            throw;
        }
        catch (OperationCanceledException)
        {
            error = "timeout";
        }
        catch (HttpRequestException)
        {
            // Includes the SSRF connect refusal (WebhookConnectException, surfaced as an
            // HttpRequestException by the handler) and any transport/TLS fault.
            error = "transport_error";
        }

        var attempts = claimed.AttemptsBeforeClaim + 1;
        WebhookLog.DeliveryFailed(_logger, claimed.Id, responseStatus, attempts);
        if (attempts >= _options.MaxAttempts)
        {
            await MarkDeadAsync(claimed.Id, responseStatus, error, cancellationToken);
            WebhookLog.DeadLettered(_logger, claimed.Id, attempts, error);
        }
        else
        {
            await RescheduleAsync(claimed.Id, responseStatus, error, Backoff(attempts), cancellationToken);
        }
    }

    private async Task<EndpointTarget?> LoadEndpointAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select url, signing_secret_encrypted, disabled_at from platform.webhook_endpoints where id = $1",
            connection)
        {
            Parameters = { new() { Value = endpointId } },
        };
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new EndpointTarget(reader.GetString(0), reader.GetString(1), !reader.IsDBNull(2));
    }

    private async Task MarkDeliveredAsync(Guid id, int responseStatus, CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "update platform.webhook_deliveries set status = 'delivered', delivered_at = now(), last_response_status = $2, last_error = null where id = $1 and status = 'pending'",
            connection)
        {
            Parameters = { new() { Value = id }, new() { Value = responseStatus } },
        };
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task RescheduleAsync(
        Guid id, int? responseStatus, string error, TimeSpan backoff, CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "update platform.webhook_deliveries set next_attempt_at = now() + make_interval(secs => $2), last_response_status = $3, last_error = $4 where id = $1 and status = 'pending'",
            connection)
        {
            Parameters =
            {
                new() { Value = id },
                new() { Value = backoff.TotalSeconds },
                new() { Value = (object?)responseStatus ?? DBNull.Value },
                new() { Value = error },
            },
        };
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task MarkDeadAsync(
        Guid id, int? responseStatus, string error, CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "update platform.webhook_deliveries set status = 'dead', dead_lettered_at = now(), last_response_status = $2, last_error = $3 where id = $1 and status = 'pending'",
            connection)
        {
            Parameters =
            {
                new() { Value = id },
                new() { Value = (object?)responseStatus ?? DBNull.Value },
                new() { Value = error },
            },
        };
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private TimeSpan Backoff(int attempts)
    {
        var seconds = Math.Min(Math.Pow(2, attempts), _options.MaxBackoff.TotalSeconds);
        return TimeSpan.FromSeconds(seconds) + (_options.MaxJitter * Random.Shared.NextDouble());
    }

    private TimeSpan ClaimLease(int attemptsBeforeClaim) => _options.SendTimeout + Backoff(attemptsBeforeClaim);

    /// <summary>A claimed delivery: its id, target endpoint, event type, stored body, and pre-claim attempt count.</summary>
    private readonly record struct ClaimedDelivery(
        Guid Id, Guid EndpointId, string EventType, string Payload, int AttemptsBeforeClaim);

    /// <summary>A loaded endpoint target: the URL, the signing-secret ciphertext, and whether it is disabled.</summary>
    private readonly record struct EndpointTarget(string Url, string Ciphertext, bool Disabled);

    private enum LeaseOutcome
    {
        Armed,
        RowUnavailable,
        LockLost,
    }
}
