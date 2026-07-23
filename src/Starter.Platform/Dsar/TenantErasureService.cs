using System.Collections.Frozen;
using System.Globalization;
using Npgsql;
using Starter.SharedKernel;

namespace Starter.Platform.Dsar;

/// <summary>
/// The default <see cref="ITenantErasureService"/>: reads and deletes every declared
/// tenant-owned table on the caller's open bypass transaction
/// (data-export-and-erasure.md section 4). The ordered table list is flattened once
/// from the registered <see cref="ITenantErasureContributor"/> declarations (DI order,
/// so <c>tenancy.tenants</c> lands last); the redaction set is the
/// <see cref="Tenancy.SensitiveAttribute"/> columns discovered by reflection over the
/// contributors' assemblies, so a new secret column is redacted the moment it is
/// annotated. Stateless apart from those cached declarations, so a singleton.
/// </summary>
internal sealed class TenantErasureService : ITenantErasureService
{
    /// <summary>The value substituted for a secret column in the operator snapshot (section 5.2, 8).</summary>
    private const string RedactedValue = "[REDACTED]";

    private readonly List<TenantTable> _tables;
    private readonly FrozenSet<string> _sensitiveColumns;
    private readonly Clock _clock;

    public TenantErasureService(IEnumerable<ITenantErasureContributor> contributors, Clock clock)
    {
        ArgumentNullException.ThrowIfNull(contributors);
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));

        var materialized = contributors.ToList();

        // Flatten in registration order; each contributor's own list is already
        // FK-safe, and the last-registered module (Tenancy) declares tenancy.tenants
        // last, so it is purged last overall.
        _tables = materialized.SelectMany(contributor => contributor.Tables).ToList();

        // The secret columns to redact in the snapshot come from every [Sensitive]
        // property on an ITenantOwned type in the modules that declare erasure tables,
        // plus Platform's own (WebhookEndpointRow lives here). Reflection-driven, so a
        // new secret column is covered by construction.
        var assemblies = materialized
            .Select(contributor => contributor.GetType().Assembly)
            .Append(typeof(TenantErasureService).Assembly);
        _sensitiveColumns = SensitiveColumns.From(assemblies);
    }

    public async Task<TenantErasureSnapshot> CaptureSnapshotAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);

        var tables = new List<TenantErasureTableSnapshot>(_tables.Count);
        foreach (var table in _tables)
        {
            tables.Add(new TenantErasureTableSnapshot(
                table.Table,
                await CaptureTableAsync(connection, transaction, table, tenantId, cancellationToken)));
        }

        return new TenantErasureSnapshot(tenantId, _clock.UtcNow, tables);
    }

    public async Task EraseAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);

        foreach (var table in _tables)
        {
            // Table and key column come only from the trusted code-side declarations
            // (never client input); the tenant id is always a bound parameter. The
            // explicit where is the safety guarantee - bypass ignores RLS.
            var sql = string.Create(
                CultureInfo.InvariantCulture,
                $"delete from {table.Table} where {table.KeyColumn} = @tenantId");
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue("tenantId", tenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Defense-in-depth (section 4): kill any live token bound to the erased
        // tenant now rather than waiting out its natural expiry. identity.sessions is
        // NOT tenant-owned (it belongs to the global Identity user), so it is not a
        // declared erasure table - the revoked rows are retained session history.
        await using var revoke = new NpgsqlCommand(
            "update identity.sessions set revoked_at = now() "
            + "where tenant_id = @tenantId and revoked_at is null",
            connection,
            transaction);
        revoke.Parameters.AddWithValue("tenantId", tenantId);
        await revoke.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> CaptureTableAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        TenantTable table,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        var sql = string.Create(
            CultureInfo.InvariantCulture,
            $"select * from {table.Table} where {table.KeyColumn} = @tenantId");
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("tenantId", tenantId);

        var rows = new List<IReadOnlyDictionary<string, object?>>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new Dictionary<string, object?>(reader.FieldCount, StringComparer.Ordinal);
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                var column = reader.GetName(ordinal);
                if (_sensitiveColumns.Contains(column))
                {
                    // Redact by name (section 5.2): the secret is captured neither in
                    // clear nor at all - it is replaced, so the compliance record is
                    // complete without leaking a credential.
                    row[column] = RedactedValue;
                }
                else
                {
                    row[column] = await reader.IsDBNullAsync(ordinal, cancellationToken)
                        ? null
                        : reader.GetValue(ordinal);
                }
            }

            rows.Add(row);
        }

        return rows;
    }
}
