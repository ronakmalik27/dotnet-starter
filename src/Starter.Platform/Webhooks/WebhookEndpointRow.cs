using Starter.Platform.Tenancy;

namespace Starter.Platform.Webhooks;

/// <summary>
/// A row of <c>platform.webhook_endpoints</c> (webhooks.md section 2): a tenant's
/// registered receiver. Tenant-owned and RLS-enforced (the second RLS-bearing table
/// in the platform schema, after <c>audit_log</c>), so a tenant admin only ever sees
/// its own endpoints.
/// <para>
/// The signing secret is stored ONLY as DataProtection ciphertext
/// (<see cref="SigningSecretEncrypted"/>) plus a short display prefix
/// (<see cref="SecretPrefix"/>); the raw secret is returned once at register/rotate
/// and never persisted in the clear (webhooks.md section 5).
/// </para>
/// </summary>
internal sealed class WebhookEndpointRow : ITenantOwned
{
    /// <summary>Primary key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The RLS discriminator, stamped from the tenant context on write.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The receiver URL. HTTPS only, validated at register (webhooks.md section 6).</summary>
    public required string Url { get; set; }

    /// <summary>An admin-facing label for the endpoint.</summary>
    public required string Description { get; set; }

    /// <summary>Subscribed event types; an empty array means all deliverable events.</summary>
    public required string[] EventTypes { get; set; }

    /// <summary>
    /// The DataProtection ciphertext of the signing secret (never the raw secret).
    /// <see cref="SensitiveAttribute"/>: a credential column that must never appear in
    /// a data export or the operator erasure snapshot (data-export-and-erasure.md
    /// section 8).
    /// </summary>
    [Sensitive]
    public required string SigningSecretEncrypted { get; set; }

    /// <summary>The first characters of the raw secret, kept in clear for display only.</summary>
    public required string SecretPrefix { get; set; }

    /// <summary>When set, the endpoint is disabled and receives no new deliveries.</summary>
    public DateTimeOffset? DisabledAt { get; set; }

    /// <summary>The user who registered the endpoint.</summary>
    public required Guid CreatedBy { get; init; }

    /// <summary>When the endpoint was registered.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>When the endpoint was last updated (register or any change).</summary>
    public required DateTimeOffset UpdatedAt { get; set; }
}
