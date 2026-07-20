using Npgsql;

namespace Starter.Platform.Events;

/// <summary>
/// Session-scoped Postgres advisory lock: exactly one
/// dispatcher leads across the old and new deployment during a rolling deploy overlap window.
/// The lock lives on a pinned connection; losing the connection IS losing
/// the lock, so the health check between batches is a ping on that
/// connection.
/// </summary>
internal sealed class AdvisoryLock(NpgsqlDataSource dataSource, long key) : IAsyncDisposable
{
    // Both lane loops ping the same pinned connection; Npgsql connections
    // are not thread-safe, so every use of it is serialized here.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private NpgsqlConnection? _connection;

    public async Task<bool> TryAcquireAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await TryAcquireCoreAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<bool> TryAcquireCoreAsync(CancellationToken cancellationToken)
    {
        var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = new NpgsqlCommand("select pg_try_advisory_lock($1)", connection)
            {
                Parameters = { new NpgsqlParameter { Value = key } },
            };

            var acquired = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
            if (!acquired)
            {
                await connection.DisposeAsync();
                return false;
            }

            _connection = connection;
            return true;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// True while the lock's session is alive. A dead session already
    /// released the lock server-side, so the caller must stop claiming.
    /// </summary>
    public async Task<bool> StillHeldAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection is null)
            {
                return false;
            }

            await using var command = new NpgsqlCommand("select 1", _connection);
            _ = await command.ExecuteScalarAsync(cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await ReleaseConnectionAsync();
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Runs <paramref name="command"/> on the lock's pinned session and
    /// returns true only if it completed there. Success proves the session
    /// - and therefore the lock - was still held when the command's effects
    /// became durable; that is the anchor for the dispatcher's per-row
    /// lease re-arm. Any failure is treated as lock loss and
    /// releases the connection, same contract as StillHeldAsync: the safe
    /// direction is to report the lock gone when in doubt.
    /// </summary>
    public async Task<bool> TryRunOnLockSessionAsync(
        Func<NpgsqlConnection, CancellationToken, Task> command,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection is null)
            {
                return false;
            }

            await command(_connection, cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await ReleaseConnectionAsync();
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync(CancellationToken.None);
        try
        {
            await ReleaseConnectionAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task ReleaseConnectionAsync()
    {
        var connection = _connection;
        _connection = null;
        if (connection is null)
        {
            return;
        }

        try
        {
            // Best effort: closing the session releases the lock anyway.
            await using var command = new NpgsqlCommand("select pg_advisory_unlock($1)", connection)
            {
                Parameters = { new NpgsqlParameter { Value = key } },
            };
            _ = await command.ExecuteScalarAsync(CancellationToken.None);
        }
        catch (Exception)
        {
            // The connection is gone; so is the lock.
        }
        finally
        {
            await connection.DisposeAsync();
        }
    }
}
