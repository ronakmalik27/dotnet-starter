namespace Starter.Platform.Auth;

/// <summary>
/// The two override scopes a tenant admin can set (feature-flags.md section 2): a
/// <see cref="Tenant"/>-wide override, or a <see cref="Workspace"/>-specific one.
/// Stable string keys stored in <c>feature_flag_overrides.scope_type</c> and used by
/// the evaluator's most-specific-wins resolution.
/// </summary>
public static class FeatureFlagScopes
{
    /// <summary>A tenant-wide override (<c>scope_id</c> is NULL).</summary>
    public const string Tenant = "tenant";

    /// <summary>A workspace-specific override (<c>scope_id</c> is the workspace id).</summary>
    public const string Workspace = "workspace";

    /// <summary>True when <paramref name="scopeType"/> is one of the two known scopes.</summary>
    public static bool IsKnown(string? scopeType) =>
        scopeType is Tenant or Workspace;
}
