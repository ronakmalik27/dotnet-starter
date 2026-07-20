using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Starter.Platform.Data;

namespace Starter.App.Persistence;

/// <summary>
/// Readiness: every schema's migrations are applied (doc 07 section 14
/// deploy contract - migrations run before the new revision takes
/// traffic, so a ready pod always sees the schema its code expects).
/// Walks the ModuleSchema descriptors the module bootstrap extensions
/// contribute to DI (ADR-0011) - the same descriptors the integration
/// fixture migrates, so the app and the suite can never disagree. The
/// verdict latches on first success: migrations only change with a new
/// revision, so a process that has seen head stays at head for its
/// lifetime and steady-state probes cost one select on the data source,
/// not nine history lookups.
/// </summary>
internal sealed class MigrationsHealthCheck(
    IServiceScopeFactory scopeFactory,
    IEnumerable<ModuleSchema> schemas) : IHealthCheck
{
    private volatile bool _knownCurrent;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (_knownCurrent)
        {
            return HealthCheckResult.Healthy("Migrations current (latched).");
        }

        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            foreach (var schema in schemas)
            {
                var dbContext = (DbContext)scope.ServiceProvider.GetRequiredService(schema.ContextType);
                var pending = await dbContext.Database.GetPendingMigrationsAsync(cancellationToken);
                if (pending.Any())
                {
                    // Schema names only; counts and migration ids stay out
                    // of the probe (unauthenticated surface, doc 10
                    // section 3) and in the health-check log.
                    return HealthCheckResult.Unhealthy($"Schema '{schema.Name}' is behind the deployed code.");
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Migration state could not be read.", exception);
        }

        _knownCurrent = true;
        return HealthCheckResult.Healthy("Migrations current.");
    }
}
