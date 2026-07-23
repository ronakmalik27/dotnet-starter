namespace Starter.Api.Auth;

/// <summary>
/// The scheme name and path prefix for the SCIM bearer authentication
/// (sso-and-scim.md section 5). The <c>Scim</c> scheme validates a <c>scim_</c>
/// bearer and mints a NON-resolving, tid-scoped principal; it is reached ONLY
/// through the forwarding policy scheme's selector, and ONLY for a request whose
/// path is under <see cref="PathPrefix"/>. That path condition is the CRITICAL
/// confinement: a <c>scim_</c> bearer on any other path falls through to JWT and
/// gets a 401, so a SCIM token can never authenticate a general tenant-admin route.
/// </summary>
public static class ScimAuthenticationDefaults
{
    /// <summary>The SCIM authentication scheme (the <see cref="ScimAuthenticationHandler"/>).</summary>
    public const string ScimScheme = "Scim";

    /// <summary>
    /// The ONLY path prefix a <c>scim_</c> bearer authenticates. Both the forwarding
    /// selector and the endpoint-group scheme pin key on it, so the confinement holds
    /// even if one were misconfigured (defense in depth).
    /// </summary>
    public const string PathPrefix = "/scim/v2";

    /// <summary>
    /// The principal-type (<c>pt</c>) claim value a SCIM principal carries: a DISTINCT
    /// value, never <c>service_account</c> or <c>user</c>, so a SCIM principal never
    /// resolves through the RBAC permission/role resolvers (CRITICAL rule 3).
    /// </summary>
    public const string PrincipalType = "scim";

    /// <summary>
    /// The synthetic <c>sub</c> a SCIM principal carries: a non-Guid marker that
    /// corresponds to NO real user, so <c>GetUserId()</c> returns null and any
    /// accidental RBAC check on a SCIM principal fails closed (CRITICAL rule 3). The
    /// SCIM surface's authority is possession of the tid-scoped bearer, not a user id.
    /// </summary>
    public const string SyntheticSubject = "scim";
}
