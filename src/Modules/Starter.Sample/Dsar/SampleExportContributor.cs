using Microsoft.EntityFrameworkCore;
using Starter.Platform.Dsar;

namespace Starter.Sample.Dsar;

/// <summary>
/// The Sample module's export contributor (data-export-and-erasure.md section 3): the
/// tenant's notes. It reads the request-scoped, RLS-bound <see cref="SampleDbContext"/>
/// inside a transaction (the interceptor sets the tenant GUC on transaction start), so
/// it only ever sees the ACTIVE tenant's rows. This is the worked example of a module
/// contributing to the export WITHOUT touching any control-plane privilege - no bypass.
/// </summary>
internal sealed class SampleExportContributor(SampleDbContext db) : IDataExportContributor
{
    public string Section => "notes";

    public async Task<object?> ExportAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Notes
            .AsNoTracking()
            .OrderBy(row => row.CreatedAt)
            .ThenBy(row => row.Id)
            .Select(row => new
            {
                row.Id,
                row.WorkspaceId,
                row.OwnerUserId,
                row.Title,
                row.Body,
                row.CreatedAt,
                row.UpdatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return rows;
    }
}
