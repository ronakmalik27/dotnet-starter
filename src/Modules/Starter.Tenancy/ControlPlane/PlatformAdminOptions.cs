using System.ComponentModel.DataAnnotations;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Platform control-plane options (config section <c>Platform</c>). Only the
/// impersonation window is bound here; the bootstrap-admin seed is read directly
/// by the composition root (multi-tenancy.md section 7). The default (15) equals
/// the access-token cap, so a zero-config host mints impersonation tokens at the
/// cap; a smaller value shortens them, and a larger value is silently clamped to
/// the cap when the grant expiry is computed (the token can never outlive the
/// 15-minute access cap).
/// </summary>
internal sealed class PlatformAdminOptions
{
    public const string SectionName = "Platform";

    /// <summary>The requested impersonation window in minutes; clamped to the 15-minute access cap.</summary>
    [Range(1, 1440)]
    public int ImpersonationMinutes { get; init; } = 15;
}
