namespace Starter.Platform.Auth;

/// <summary>
/// The wire values for a role-assignment principal (multi-tenancy.md section 13):
/// the contract the API composition layer passes to
/// <c>ITenancyApi.AssignRoleAsync</c> and the Tenancy module validates. Declared
/// in the platform so the endpoint layer names the principal kind without a magic
/// string. The Tenancy module's internal <c>PrincipalType</c> stores the same
/// literals in the database; the two must stay in lockstep (both "user" and
/// "team").
/// </summary>
public static class PrincipalTypes
{
    /// <summary>A grant bound to one user (principal_id is a user id).</summary>
    public const string User = "user";

    /// <summary>A grant bound to a team (principal_id is a team id); it unions into every member's effective set.</summary>
    public const string Team = "team";
}
