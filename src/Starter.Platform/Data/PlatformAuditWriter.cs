using Npgsql;
using NpgsqlTypes;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Platform.Data;

/// <summary>
/// The default <see cref="IPlatformAuditWriter"/>: a single parameterized INSERT
/// on the caller's open connection and transaction, so the platform audit row
/// commits with the grant/revoke it records. Stateless apart from the clock
/// (recorded_at is stamped at write time), so it is a singleton. It never opens
/// its own connection - the write MUST join the action's transaction.
/// </summary>
internal sealed class PlatformAuditWriter(Clock clock) : IPlatformAuditWriter
{
    private const string InsertSql = """
        insert into platform.platform_audit_log
          (id, occurred_at, recorded_at, action, actor_user_id, subject_user_id, summary, data)
        values (@id, @occurred, @recorded, @action, @actor, @subject, @summary, @data)
        """;

    public async Task WriteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        DomainEventRecord sourceEvent,
        Guid? subjectUserId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(sourceEvent);

        await using var command = new NpgsqlCommand(InsertSql, connection, transaction);
        command.Parameters.AddWithValue("id", sourceEvent.Id);
        command.Parameters.AddWithValue("occurred", sourceEvent.OccurredAt);
        command.Parameters.AddWithValue("recorded", clock.UtcNow);
        command.Parameters.AddWithValue("action", sourceEvent.EventType);
        // Explicitly typed uuid so a null actor/subject binds as a uuid NULL
        // rather than relying on Npgsql to infer the type of an untyped null.
        command.Parameters.Add(new NpgsqlParameter("actor", NpgsqlDbType.Uuid)
        {
            Value = (object?)sourceEvent.ActorUserId ?? DBNull.Value,
        });
        command.Parameters.Add(new NpgsqlParameter("subject", NpgsqlDbType.Uuid)
        {
            Value = (object?)subjectUserId ?? DBNull.Value,
        });
        command.Parameters.AddWithValue("summary", AuditSummary.Render(sourceEvent));
        command.Parameters.Add(new NpgsqlParameter("data", NpgsqlDbType.Jsonb)
        {
            Value = sourceEvent.Payload,
        });
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
