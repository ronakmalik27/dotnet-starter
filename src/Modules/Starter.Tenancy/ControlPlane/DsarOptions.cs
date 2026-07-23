using System.ComponentModel.DataAnnotations;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Data-subject-request options (config section <c>Dsar</c>,
/// data-export-and-erasure.md section 2). The retention window is the grace period
/// after a soft-delete before a tenant may be hard-deleted (erased): a soft-deleted
/// tenant stays recoverable (reactivate) for this long, the standard "restore within
/// N days" model. The default (30) satisfies the annotation, so a zero-config host
/// still boots; the [Range] is enforced at startup (ValidateOnStart).
/// </summary>
internal sealed class DsarOptions
{
    public const string SectionName = "Dsar";

    /// <summary>The retention window after soft-delete, in days, before erasure is permitted.</summary>
    [Range(1, 3650)]
    public int RetentionDays { get; init; } = 30;
}
