using System.Text.Json.Serialization;

namespace Starter.Platform.Dsar;

/// <summary>
/// Assembles the tenant data export bundle (data-export-and-erasure.md section 3):
/// resolves every <see cref="IDataExportContributor"/>, invokes each under the
/// caller's own RLS-bound context, and collects the named sections. Request-path
/// only, under row-level security - it never touches the bypass data source.
/// </summary>
public interface ITenantExportService
{
    /// <summary>
    /// Builds the bundle for the ACTIVE tenant (resolved from the request-scoped
    /// tenant context). Synchronous assembly is fine for a starter; a large-tenant
    /// async export to an object-store artifact is a documented grow-into (section 9).
    /// </summary>
    Task<TenantExportBundle> ExportAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The assembled export bundle (data-export-and-erasure.md section 3). Serialized as
/// the <c>GET /api/v1/tenant/export</c> response: <c>formatVersion</c>,
/// <c>tenantId</c>, <c>generatedAt</c>, and the named <c>sections</c>.
/// <see cref="SectionCounts"/> is the per-section row-count summary that rides the
/// <c>tenancy.tenant.data_exported</c> audit event; it is not part of the wire
/// response.
/// </summary>
public sealed record TenantExportBundle(
    int FormatVersion,
    Guid TenantId,
    DateTimeOffset GeneratedAt,
    IReadOnlyDictionary<string, object?> Sections,
    [property: JsonIgnore] IReadOnlyDictionary<string, int> SectionCounts);
