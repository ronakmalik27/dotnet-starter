namespace Starter.Platform.Dsar;

/// <summary>
/// A module's contribution of one named section to a tenant data export
/// (data-export-and-erasure.md section 3, GDPR Art. 15/20). Each module implements
/// one or more of these, each reading its OWN request-scoped, RLS-bound context -
/// NO bypass anywhere, so <c>Sample</c> and every other module contribute without
/// touching a control-plane privilege. <see cref="ITenantExportService"/> resolves
/// the full <c>IEnumerable</c> (the same per-module DI contributor seam as
/// <c>IDomainEventConsumer</c>) and assembles the bundle.
/// <para>
/// A contributor MUST exclude secret material by shaping its section: the
/// service-account section omits <c>key_hash</c>, the webhook-endpoint section omits
/// the encrypted signing secret (section 8). The <c>[Sensitive]</c> completeness test
/// fails the build if any secret ever appears in the bundle.
/// </para>
/// </summary>
public interface IDataExportContributor
{
    /// <summary>The bundle section name this contributor fills, e.g. <c>memberships</c>. Unique across contributors.</summary>
    string Section { get; }

    /// <summary>
    /// The section's data for the ACTIVE tenant, shaped and secret-excluded: a
    /// collection of rows, or a single object (the tenant profile), or null. Read
    /// under the caller's own RLS-bound context.
    /// </summary>
    Task<object?> ExportAsync(CancellationToken cancellationToken);
}
