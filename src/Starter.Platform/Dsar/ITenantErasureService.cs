using Npgsql;

namespace Starter.Platform.Dsar;

/// <summary>
/// Purges a target tenant's rows on the bypass path (data-export-and-erasure.md
/// section 4, GDPR Art. 17). It is Platform-executed - the only privileged half of
/// erasure - so modules stay bypass-free and only declare their tables via
/// <see cref="ITenantErasureContributor"/>. Both methods run on the caller's ALREADY
/// OPEN bypass connection and transaction (the same shape as
/// <c>IPlatformAuditWriter</c>), so the hard-delete's snapshot, deletes, session
/// revoke, and audit row all commit in ONE transaction.
/// <para>
/// EVERY statement carries an explicit, parameterized <c>where tenant_id = @tenantId</c>
/// (<c>tenancy.tenants</c>: <c>where id = @tenantId</c>). This is the safety guarantee:
/// the bypass role ignores RLS, so a missing filter would purge every tenant. A test
/// proves erasing tenant A leaves tenant B intact in every table.
/// </para>
/// </summary>
public interface ITenantErasureService
{
    /// <summary>
    /// The operator's pre-purge compliance record (data-export-and-erasure.md section
    /// 5.2): <c>select * from {table} where {key} = @tenantId</c> for every declared
    /// table, into a raw row snapshot with the <see cref="Tenancy.SensitiveAttribute"/>
    /// columns REDACTED. Read on the caller's transaction, BEFORE
    /// <see cref="EraseAsync"/> deletes the rows.
    /// </summary>
    Task<TenantErasureSnapshot> CaptureSnapshotAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes every declared table's rows for <paramref name="tenantId"/> (children
    /// before parents, <c>tenancy.tenants</c> last) and revokes the tenant's live
    /// sessions (<c>update identity.sessions set revoked_at = now() where
    /// tenant_id = @tenantId and revoked_at is null</c>, defense-in-depth, section 4).
    /// All on the caller's transaction.
    /// </summary>
    Task EraseAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid tenantId,
        CancellationToken cancellationToken);
}

/// <summary>
/// The operator's pre-purge raw row snapshot (data-export-and-erasure.md section
/// 5.2): every declared table's rows for the tenant, secret columns redacted. Distinct
/// from the shaped self-serve export - one raw for the operator, one shaped for the
/// subject, both drawn from the same tenant. Returned in the erase response so the
/// operator captures it.
/// </summary>
public sealed record TenantErasureSnapshot(
    Guid TenantId,
    DateTimeOffset CapturedAt,
    IReadOnlyList<TenantErasureTableSnapshot> Tables);

/// <summary>One declared table's captured rows (each a column-name -&gt; value map, secrets redacted).</summary>
public sealed record TenantErasureTableSnapshot(
    string Table,
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows);
