using System.Collections;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Dsar;

/// <summary>
/// The default <see cref="ITenantExportService"/>: invokes every registered
/// <see cref="IDataExportContributor"/> in turn and collects its section into the
/// bundle (data-export-and-erasure.md section 3). Each contributor reads its own
/// module's RLS-bound context, so the whole assembly stays on the request path
/// under row-level security - there is no bypass here. Contributors run
/// sequentially: several share one request-scoped module DbContext, and each opens
/// its own read transaction, so they must not overlap.
/// </summary>
internal sealed class TenantExportService(
    IEnumerable<IDataExportContributor> contributors,
    ITenantContext tenant,
    Clock clock) : ITenantExportService
{
    /// <summary>The bundle schema version (data-export-and-erasure.md section 3).</summary>
    private const int CurrentFormatVersion = 1;

    public async Task<TenantExportBundle> ExportAsync(CancellationToken cancellationToken)
    {
        var sections = new Dictionary<string, object?>(StringComparer.Ordinal);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var contributor in contributors)
        {
            var section = await contributor.ExportAsync(cancellationToken);
            sections[contributor.Section] = section;
            counts[contributor.Section] = Count(section);
        }

        return new TenantExportBundle(
            CurrentFormatVersion,
            tenant.TenantId,
            clock.UtcNow,
            sections,
            counts);
    }

    // A collection section counts its rows; a single object (the tenant profile)
    // counts as one; a null section counts as zero. A string is a scalar, not a
    // collection, so it is never enumerated as rows.
    private static int Count(object? section) => section switch
    {
        null => 0,
        string => 1,
        ICollection collection => collection.Count,
        IEnumerable enumerable => enumerable.Cast<object?>().Count(),
        _ => 1,
    };
}
