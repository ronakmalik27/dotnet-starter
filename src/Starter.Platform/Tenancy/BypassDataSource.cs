using Npgsql;

namespace Starter.Platform.Tenancy;

/// <summary>
/// The RLS-exempt escape hatch, deliberately a distinct type so request-scoped
/// code cannot resolve it by asking for an <see cref="NpgsqlDataSource"/>: the
/// normal (request) data source is registered as <see cref="NpgsqlDataSource"/>
/// and is a non-superuser, non-BYPASSRLS role subject to row-level security;
/// this one is backed by a <c>BYPASSRLS</c> role and is used only by
/// migrations, bootstrap, and the small set of explicitly cross-tenant jobs.
/// Crossing tenants is a role reached through a separate connection source,
/// never an in-band GUC or flag a normal session can flip.
/// </summary>
public sealed class BypassDataSource(NpgsqlDataSource dataSource) : IAsyncDisposable
{
    /// <summary>The underlying BYPASSRLS-backed data source.</summary>
    public NpgsqlDataSource DataSource { get; } =
        dataSource ?? throw new ArgumentNullException(nameof(dataSource));

    public ValueTask DisposeAsync() => DataSource.DisposeAsync();
}
