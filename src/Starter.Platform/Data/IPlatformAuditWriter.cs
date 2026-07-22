using Npgsql;
using Starter.Platform.Events;

namespace Starter.Platform.Data;

/// <summary>
/// Writes one <c>platform.platform_audit_log</c> row inside the caller's open
/// transaction (audit-log.md sections 2, 4). The two null-tenant platform-admin
/// actions - <c>platform.admin.granted</c> and <c>platform.admin.revoked</c> -
/// are audited SYNCHRONOUSLY, in the same bypass transaction that grants or
/// revokes the admin, so the audit row and the action commit together (strictly
/// stronger than an eventual projection for the highest-sensitivity actions).
/// <para>
/// The call site lives in the Tenancy control plane (<c>PlatformAdminService</c>),
/// which cannot see the internal <c>PlatformDbContext</c> and so must not
/// hand-roll the insert. It calls this Platform-registered writer, passing its
/// already-open connection and transaction, so Platform owns the column list in
/// one place. The row's primary key equals the emitted event's id, and the
/// writer is invoked only on the branch that actually commits and emits the
/// event (so there is never an audit row without a real action, and never a
/// duplicate).
/// </para>
/// </summary>
public interface IPlatformAuditWriter
{
    /// <summary>
    /// Inserts the platform audit row for <paramref name="sourceEvent"/> on the
    /// caller's <paramref name="connection"/> / <paramref name="transaction"/>.
    /// The row derives id / occurred-at / action / actor / data from the event;
    /// <paramref name="subjectUserId"/> is the user the action was about.
    /// </summary>
    Task WriteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        DomainEventRecord sourceEvent,
        Guid? subjectUserId,
        CancellationToken cancellationToken);
}
