using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace Starter.App.Persistence;

/// <summary>
/// The readiness half of the issue #99 architect finding: readyz probes
/// the same NpgsqlDataSource every request-path write rides, so the
/// no-persistence failure mode can never hide behind a ready signal.
/// Descriptions stay generic - probe responses are unauthenticated
/// surface (doc 10 section 3); the exception goes to the health-check
/// log, not the wire.
/// </summary>
internal sealed class PostgresHealthCheck(NpgsqlDataSource dataSource) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var probe = new NpgsqlCommand("select 1", connection);
            _ = await probe.ExecuteScalarAsync(cancellationToken);
            return HealthCheckResult.Healthy("Postgres reachable.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Postgres is unreachable.", exception);
        }
    }
}
