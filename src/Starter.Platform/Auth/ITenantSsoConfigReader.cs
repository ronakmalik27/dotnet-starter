namespace Starter.Platform.Auth;

/// <summary>
/// A tenant's resolved enterprise-SSO configuration, as the Identity module needs
/// it to drive the OIDC flow: the IdP issuer, the client id (the id_token
/// audience), the DECRYPTED client secret (for the server-side code exchange), and
/// whether SSO is currently enabled. The secret is decrypted by the Tenancy-side
/// implementation before it crosses this seam, so the Identity module never sees
/// the ciphertext and never touches DataProtection for SSO - the same in-memory
/// posture the first-party Google flow has for its options-bound secret.
/// </summary>
public sealed record TenantSsoConfig(
    Guid TenantId,
    string Issuer,
    string ClientId,
    string ClientSecret,
    bool Enabled);

/// <summary>
/// The narrow seam the SSO sign-in flow uses to read a tenant's per-tenant OIDC
/// configuration and to route an email domain to its owning tenant
/// (sso-and-scim.md sections 3, 4), declared in the platform so the Identity
/// module - which owns the OIDC flow - never references the Tenancy module or its
/// <c>tenancy.sso_configs</c> / <c>tenancy.sso_domain_claims</c> tables (the
/// module-boundary arch test forbids it). This mirrors the existing
/// <see cref="ITenantSessionPolicyReader"/> / <see cref="ITenantRoleReader"/>
/// ports: the Tenancy module implements it and the composition root bridges the
/// port to that implementation, so Identity depends on the port and there is one
/// lookup with no drift.
/// <para>
/// Both lookups run cross-tenant on the bypass path: at <c>/auth/sso/start</c>
/// there is no active tenant yet (the tenant is derived FROM the email domain or a
/// <c>?tenantId</c>), and at <c>/auth/sso/callback</c> the tenant comes only from
/// the server-side state record - never a request-scoped tid - so an RLS-bound
/// read keyed on the current-tenant GUC would see nothing.
/// </para>
/// </summary>
public interface ITenantSsoConfigReader
{
    /// <summary>
    /// Resolves the tenant that owns a routing domain, EXACT case-insensitive on
    /// the full domain and only when the claim is VERIFIED (<c>verified_at</c> set)
    /// - never a suffix/substring test (sso-and-scim.md section 3). An unverified or
    /// unclaimed domain resolves to null (does not route), so a domain nobody has
    /// proven cannot capture a login. The global unique index on the normalized
    /// domain guarantees at most one tenant can match.
    /// </summary>
    Task<Guid?> ResolveTenantByVerifiedDomainAsync(string domain, CancellationToken cancellationToken);

    /// <summary>
    /// Reads a tenant's SSO configuration with the client secret DECRYPTED, or null
    /// when the tenant has none. The caller re-checks <see cref="TenantSsoConfig.Enabled"/>
    /// at the point of use (an admin disabling SSO mid-incident is an immediate kill
    /// switch). A missing config is null.
    /// </summary>
    Task<TenantSsoConfig?> GetConfigAsync(Guid tenantId, CancellationToken cancellationToken);
}
