using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Starter.Platform.Data;

namespace Starter.Platform.Tenancy;

/// <summary>
/// The one seam that binds a unit of work to its tenant. When a transaction
/// starts (or an external transaction is enlisted via UseTransaction, the
/// idempotency-filter path), this issues
/// <c>set_config('app.current_tenant', &lt;tenant&gt;, true)</c> on that
/// transaction's connection, so PostgreSQL row-level security scopes every
/// statement inside it. <c>set_config(..., is_local =&gt; true)</c> is the
/// function form of <c>SET LOCAL</c>: the value lives exactly for the
/// transaction and is gone when it ends, independent of connection pooling,
/// so a pooled connection can never carry one request's tenant into another's.
/// <para>
/// It reads the tenant off the DbContext that owns the transaction (an
/// instance member, never ambient state), and does nothing when no tenant is
/// resolved: a query with no tenant then matches the RLS policy's NULL GUC and
/// returns zero rows (fail-closed), never a leak. Stateless, so a single
/// shared instance is registered on every context's options.
/// </para>
/// </summary>
internal sealed class TenantTransactionInterceptor : DbTransactionInterceptor
{
    internal static readonly TenantTransactionInterceptor Instance = new();

    private const string SetTenantSql = "select set_config('app.current_tenant', @tenant, true)";

    private TenantTransactionInterceptor()
    {
    }

    public override DbTransaction TransactionStarted(
        DbConnection connection,
        TransactionEndEventData eventData,
        DbTransaction result)
    {
        SetTenant(connection, result, eventData.Context);
        return result;
    }

    public override async ValueTask<DbTransaction> TransactionStartedAsync(
        DbConnection connection,
        TransactionEndEventData eventData,
        DbTransaction result,
        CancellationToken cancellationToken = default)
    {
        await SetTenantAsync(connection, result, eventData.Context, cancellationToken);
        return result;
    }

    public override DbTransaction TransactionUsed(
        DbConnection connection,
        TransactionEventData eventData,
        DbTransaction result)
    {
        SetTenant(connection, result, eventData.Context);
        return result;
    }

    public override async ValueTask<DbTransaction> TransactionUsedAsync(
        DbConnection connection,
        TransactionEventData eventData,
        DbTransaction result,
        CancellationToken cancellationToken = default)
    {
        await SetTenantAsync(connection, result, eventData.Context, cancellationToken);
        return result;
    }

    private static void SetTenant(
        DbConnection connection,
        DbTransaction transaction,
        Microsoft.EntityFrameworkCore.DbContext? context)
    {
        if (!TryTenantId(context, out var tenantId))
        {
            return;
        }

        using var command = CreateCommand(connection, transaction, tenantId);
        command.ExecuteNonQuery();
    }

    private static async ValueTask SetTenantAsync(
        DbConnection connection,
        DbTransaction transaction,
        Microsoft.EntityFrameworkCore.DbContext? context,
        CancellationToken cancellationToken)
    {
        if (!TryTenantId(context, out var tenantId))
        {
            return;
        }

        await using var command = CreateCommand(connection, transaction, tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static bool TryTenantId(Microsoft.EntityFrameworkCore.DbContext? context, out Guid tenantId)
    {
        tenantId = Guid.Empty;
        if (context is ModuleDbContext moduleContext && moduleContext.TenantContext.IsResolved)
        {
            tenantId = moduleContext.TenantContext.TenantId;
            return true;
        }

        return false;
    }

    private static DbCommand CreateCommand(DbConnection connection, DbTransaction transaction, Guid tenantId)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = SetTenantSql;
        var parameter = command.CreateParameter();
        parameter.ParameterName = "tenant";
        // Text; the policy casts current_setting back to uuid. A Guid renders
        // as a fixed hyphenated hex form, so there is nothing to inject.
        parameter.Value = tenantId.ToString();
        command.Parameters.Add(parameter);
        return command;
    }
}
