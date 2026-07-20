using Npgsql;
using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The AdvisoryLock released-state contract the dispatcher's abort paths
/// rely on: with no acquired session, every operation reports the lock
/// as not held - StillHeldAsync and
/// TryRunOnLockSessionAsync return false without touching the database,
/// and disposal is safe and idempotent. The alive-session half of the
/// contract runs against real Postgres in the integration suite
/// (OutboxTests connection-kill handover).
/// </summary>
public class AdvisoryLockTests
{
    // Never connected to: the null-connection paths must not do I/O.
    private static NpgsqlDataSource UnusedDataSource() =>
        NpgsqlDataSource.Create("Host=127.0.0.1;Port=1;Username=unused;Password=unused;Database=unused");

    [Fact]
    public async Task StillHeld_WithoutAcquire_ReportsNotHeld()
    {
        await using var dataSource = UnusedDataSource();
        await using var advisoryLock = new AdvisoryLock(dataSource, key: 42);

        (await advisoryLock.StillHeldAsync(TestContext.Current.CancellationToken)).ShouldBeFalse();
    }

    [Fact]
    public async Task TryRunOnLockSession_WithoutAcquire_ReportsNotHeld_AndNeverRunsTheCommand()
    {
        await using var dataSource = UnusedDataSource();
        await using var advisoryLock = new AdvisoryLock(dataSource, key: 42);
        var ran = false;

        var held = await advisoryLock.TryRunOnLockSessionAsync(
            (_, _) =>
            {
                ran = true;
                return Task.CompletedTask;
            },
            TestContext.Current.CancellationToken);

        // The lease re-arm must never execute off-session: a command that
        // ran anywhere else could arm a lease without proving leadership.
        held.ShouldBeFalse();
        ran.ShouldBeFalse();
    }

    [Fact]
    public async Task Dispose_WithoutAcquire_IsSafeAndIdempotent()
    {
        await using var dataSource = UnusedDataSource();
        var advisoryLock = new AdvisoryLock(dataSource, key: 42);

        await advisoryLock.DisposeAsync();
        await advisoryLock.DisposeAsync();

        (await advisoryLock.StillHeldAsync(TestContext.Current.CancellationToken)).ShouldBeFalse();
    }
}
