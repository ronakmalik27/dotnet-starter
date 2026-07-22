using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The dispatcher's election-failure contract: an instance that cannot
/// reach Postgres logs the loss, stays a follower, keeps re-entering the
/// election instead of dying, and still shuts down cleanly. The
/// leader-side behavior (claiming, sending, the lease re-arm, the
/// connection-kill handover) runs against real Postgres in the integration
/// suite.
/// </summary>
public class OutboxDispatcherTests
{
    [Fact]
    public async Task Election_AgainstUnreachablePostgres_LogsLossKeepsRetrying_AndStopsCleanly()
    {
        // Port 1 on loopback refuses immediately: the election fails fast
        // without any live Postgres.
        await using var dataSource = NpgsqlDataSource.Create(
            "Host=127.0.0.1;Port=1;Username=unused;Password=unused;Database=unused");
        var logger = new RecordingLogger();
        // No consumers, so no consume scope is ever created; a bare provider's
        // scope factory satisfies the dependency without being exercised.
        await using var services = new ServiceCollection().BuildServiceProvider();
        using var dispatcher = new OutboxDispatcher(
            dataSource,
            Options.Create(new OutboxOptions { LeaderRetryInterval = TimeSpan.FromMilliseconds(20) }),
            [],
            new OutboxMetrics(),
            TimeProvider.System,
            services.GetRequiredService<IServiceScopeFactory>(),
            logger);

        await dispatcher.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            // Two logged losses prove the re-entry loop, not just one failure.
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
            while (logger.Count(nameof(OutboxLog.LeadershipLost)) < 2 && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            logger.Count(nameof(OutboxLog.LeadershipLost)).ShouldBeGreaterThanOrEqualTo(2);
            dispatcher.IsLeaderForTests.ShouldBeFalse();
        }
        finally
        {
            await dispatcher.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    private sealed class RecordingLogger : ILogger<OutboxDispatcher>
    {
        private readonly ConcurrentQueue<string> _events = new();

        public int Count(string eventName) => _events.Count(name => name == eventName);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => _events.Enqueue(eventId.Name ?? string.Empty);
    }
}
