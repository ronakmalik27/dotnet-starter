using Npgsql;
using Starter.Tenancy.Sso;
using Starter.Platform.Auth;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The <see cref="ITenantSsoConfigReader"/> implementation for the SSO sign-in flow
/// (sso-and-scim.md sections 3, 4), run on the bypass data source. Like
/// <see cref="MembershipDirectory"/> and <see cref="TenantSessionPolicyReader"/> it
/// is explicitly cross-tenant: at <c>/auth/sso/start</c> there is no active tenant
/// yet (the tenant is derived from the email domain or a <c>?tenantId</c>), and at
/// <c>/auth/sso/callback</c> the tenant comes only from the server-side state
/// record - never a request-scoped tid - so an RLS-bound read keyed on the
/// current-tenant GUC would see nothing. Reading a domain claim and a tenant's own
/// SSO config across the boundary is exactly what the bypass role is for. This is
/// one of the Tenancy types the bypass-containment arch test allowlists.
/// <para>
/// It decrypts the client secret here (owning the DataProtection protector), so the
/// Identity module receives a plaintext secret by value over the port and never
/// touches the ciphertext or DataProtection for SSO. A key-ring failure fails
/// closed to null (a generic "no usable config"), never an unhandled 500.
/// </para>
/// </summary>
internal sealed class TenantSsoConfigReader(BypassDataSource bypass, SsoClientSecretProtector secrets)
    : ITenantSsoConfigReader
{
    public async Task<Guid?> ResolveTenantByVerifiedDomainAsync(string domain, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var normalized = domain.Trim().ToLowerInvariant();

        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        // EXACT match on the full domain (citext is case-insensitive) and only when
        // the claim is VERIFIED - never a suffix/substring test, and never an
        // unverified claim (sso-and-scim.md section 3). The global unique index
        // guarantees at most one row matches.
        await using var command = new NpgsqlCommand(
            "select tenant_id from tenancy.sso_domain_claims "
            + "where domain = @domain and verified_at is not null limit 1",
            connection);
        command.Parameters.AddWithValue("domain", normalized);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? null : (Guid)result;
    }

    public async Task<TenantSsoConfig?> GetConfigAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await using var connection = await bypass.DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select issuer, client_id, client_secret_encrypted, enabled from tenancy.sso_configs "
            + "where tenant_id = @tenant limit 1",
            connection);
        command.Parameters.AddWithValue("tenant", tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var issuer = reader.GetString(0);
        var clientId = reader.GetString(1);
        var encrypted = reader.GetString(2);
        var enabled = reader.GetBoolean(3);

        string clientSecret;
        try
        {
            clientSecret = secrets.Unprotect(encrypted);
        }
        catch (SsoClientSecretUnprotectException)
        {
            // A lost or rotated-away key ring: fail closed to "no usable config"
            // (a generic SSO failure at the callback), never an unhandled 500.
            return null;
        }

        return new TenantSsoConfig(tenantId, issuer, clientId, clientSecret, enabled);
    }
}
