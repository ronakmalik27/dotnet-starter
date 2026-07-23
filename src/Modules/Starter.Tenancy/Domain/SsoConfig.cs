using Starter.Platform.Tenancy;

namespace Starter.Tenancy.Domain;

/// <summary>
/// A tenancy.sso_configs row: one tenant's enterprise-SSO OIDC IdP
/// (sso-and-scim.md section 2). Tenant-owned, but uniquely its OWN tenant_id is
/// the primary key (one IdP per tenant), so the RLS policy keys on tenant_id and
/// the query filter does too. The client secret is stored ONLY encrypted (a
/// DataProtection ciphertext), write-only over the admin API and decrypted only
/// on the server-side code exchange.
/// </summary>
internal sealed class SsoConfig : ITenantOwned
{
    /// <summary>The owning tenant IS the primary key (one IdP per tenant).</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The IdP's OIDC issuer (authority). MUST be https, enforced at save.</summary>
    public required string Issuer { get; set; }

    /// <summary>The app's client id at the IdP - the id_token audience.</summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// The client secret, DataProtection-encrypted at rest.
    /// <see cref="SensitiveAttribute"/>: a credential column that must never appear
    /// in a data export or the operator erasure snapshot (sso-and-scim.md sections
    /// 2, 9 - the same completeness mechanism as service_accounts.key_hash and the
    /// webhook signing secret).
    /// </summary>
    [Sensitive]
    public required string ClientSecretEncrypted { get; set; }

    /// <summary>SSO is off until an admin turns it on; re-checked at callback time.</summary>
    public required bool Enabled { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// A tenancy.sso_domain_claims row: one email domain a tenant claims for SSO
/// routing (sso-and-scim.md sections 2, 3). Tenant-owned in the ordinary way (a
/// real tenant_id column). The normalized <see cref="Domain"/> carries a GLOBAL
/// unique index (citext), so a domain is claimable by at most ONE tenant - a
/// duplicate claim is a constraint violation, not merely a policy expectation. A
/// claim ROUTES only once <see cref="VerifiedAt"/> is set (operator approval, or
/// the deferred DNS-TXT verification); an unverified claim never routes.
/// </summary>
internal sealed class SsoDomainClaim : ITenantOwned
{
    public required Guid Id { get; init; }

    public required Guid TenantId { get; init; }

    /// <summary>The claimed email domain, case-insensitive (citext), globally unique.</summary>
    public required string Domain { get; init; }

    /// <summary>When the claim was verified (operator approval / DNS-TXT), or null while unverified. Only a verified claim routes.</summary>
    public DateTimeOffset? VerifiedAt { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}
