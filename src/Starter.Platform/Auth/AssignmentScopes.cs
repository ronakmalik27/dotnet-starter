namespace Starter.Platform.Auth;

/// <summary>
/// The wire values for a role-assignment scope (multi-tenancy.md section 13): the
/// contract the API composition layer passes to <c>ITenancyApi.AssignRoleAsync</c>
/// and the Tenancy module validates. Declared in the platform so the endpoint
/// layer names the scope without a magic string. The Tenancy module's internal
/// <c>AssignmentScope</c> stores the same literals in the database; the two must
/// stay in lockstep (both "tenant" and "workspace").
/// </summary>
public static class AssignmentScopes
{
    /// <summary>A grant that applies tenant-wide (scope_id null); inherits into every workspace.</summary>
    public const string Tenant = "tenant";

    /// <summary>A grant that applies to one workspace only (scope_id = the workspace id).</summary>
    public const string Workspace = "workspace";
}
