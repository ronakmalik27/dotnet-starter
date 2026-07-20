using Microsoft.EntityFrameworkCore;

namespace Starter.Platform.Data;

/// <summary>
/// The one place DbContext options are composed, so every context - app
/// runtime, design time, and tests - gets identical behavior: Npgsql,
/// snake_case names (doc 07 section 1), and a per-schema migrations
/// history table (each module owns its schema end to end).
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
            .UseSnakeCaseNamingConvention();
    }
}
