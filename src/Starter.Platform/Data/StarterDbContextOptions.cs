using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Data;

/// <summary>
/// The one place DbContext options are composed, so every context - app
/// runtime, design time, and tests - gets identical behavior: Npgsql,
/// snake_case names, a per-schema migrations history table (each module owns
/// its schema end to end), and the tenant transaction interceptor that issues
/// the RLS GUC.
/// </summary>
public static class StarterDbContextOptions
{
    public const string MigrationsHistoryTable = "__ef_migrations_history";

    public static DbContextOptionsBuilder<TContext> ForSchema<TContext>(
        string connectionString,
        string schema)
        where TContext : DbContext
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);

        var builder = new DbContextOptionsBuilder<TContext>();
        Apply(builder, connectionString, schema);
        return builder;
    }

    public static void Apply(
        DbContextOptionsBuilder builder,
        string connectionString,
        string schema)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(schema);

        builder
            .UseNpgsql(
                connectionString,
                npgsql => npgsql.MigrationsHistoryTable(MigrationsHistoryTable, schema))
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(TenantTransactionInterceptor.Instance);
    }

    /// <summary>
    /// Options for a context enlisted onto an already-open connection (the
    /// idempotency-filter path): the connection is shared, so there is no
    /// connection string and no migrations-history mapping, but the snake_case
    /// convention and the tenant interceptor still apply - the interceptor
    /// fires on UseTransaction and sets the GUC on the shared connection.
    /// </summary>
    public static DbContextOptionsBuilder<TContext> ForConnection<TContext>(DbConnection connection)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(connection);

        return new DbContextOptionsBuilder<TContext>()
            .UseNpgsql(connection)
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(TenantTransactionInterceptor.Instance);
    }
}
