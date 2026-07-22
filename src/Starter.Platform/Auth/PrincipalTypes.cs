namespace Starter.Platform.Auth;

/// <summary>
/// The wire values for a role-assignment principal (multi-tenancy.md section 13):
/// the contract the API composition layer passes to
/// <c>ITenancyApi.AssignRoleAsync</c> and the Tenancy module validates. Declared
/// in the platform so the endpoint layer names the principal kind without a magic
/// string. The Tenancy module's internal <c>PrincipalType</c> stores the same
/// literals in the database; the two must stay in lockstep ("user", "team", and
/// "service_account").
/// </summary>
public static class PrincipalTypes
{
    /// <summary>A grant bound to one user (principal_id is a user id).</summary>
    public const string User = "user";

    /// <summary>A grant bound to a team (principal_id is a team id); it unions into every member's effective set.</summary>
    public const string Team = "team";

    /// <summary>
    /// A grant bound to a service account (principal_id is a service_account id):
    /// a non-human principal that authenticates with a hashed API key and carries
    /// NO membership, so its effective permissions are exactly its grants
    /// (service-accounts.md sections 1, 4).
    /// </summary>
    public const string ServiceAccount = "service_account";
}
