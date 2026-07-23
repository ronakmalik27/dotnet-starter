namespace Starter.Platform.Tenancy;

/// <summary>
/// Marks a property that holds credential or secret material and must NEVER leave
/// the system in a portable artifact - the self-serve export bundle
/// (data-export-and-erasure.md section 3) or the operator pre-purge snapshot
/// (section 5.2). Two tenant-owned columns carry it today
/// (<c>service_accounts.key_hash</c> and the webhook endpoint's encrypted signing
/// secret); a future secret column (an SSO client secret, an outbound-API token)
/// adds the attribute and is caught by construction.
/// <para>
/// The guarantee is a COMPLETENESS mechanism, not an enumerated list (section 8):
/// the operator snapshot redacts every column that maps to a <c>[Sensitive]</c>
/// property on any <see cref="ITenantOwned"/> type (reflection-driven, so a new
/// secret column is redacted the moment it is annotated), the export contributors
/// shape their DTOs to exclude them, and a reflection test fails the build if a
/// <c>[Sensitive]</c> value ever appears in either artifact - mirroring the audit
/// log's own <c>CatalogueCompleteness</c> discipline.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class SensitiveAttribute : Attribute;
