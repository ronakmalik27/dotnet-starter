namespace Starter.Platform.Tenancy;

/// <summary>
/// Where a tenant identifier may come from, in the order the middleware tries
/// them. The default order (see <see cref="TenantResolutionOptions"/>) puts the
/// signed claim first (authoritative once signed in) and the header last (the
/// explicit client/test override).
/// </summary>
public enum TenantSource
{
    /// <summary>The <c>tid</c> claim on the authenticated principal.</summary>
    Claim,

    /// <summary>The first label of the request host (<c>acme.app.example.com</c> -&gt; <c>acme</c>).</summary>
    Subdomain,

    /// <summary>The path prefix <c>/t/{slug}/</c>.</summary>
    Path,

    /// <summary>The <c>X-Tenant</c> request header.</summary>
    Header,
}

/// <summary>
/// Configures tenant resolution: the source order (bindable, so a deployment
/// that fronts tenants by subdomain can reorder without code) and the header
/// name. The defaults match the blueprint.
/// </summary>
public sealed class TenantResolutionOptions
{
    /// <summary>The configuration section this binds from.</summary>
    public const string SectionName = "Tenancy:Resolution";

    /// <summary>Source order, first match wins. Defaults to claim, subdomain, path, header.</summary>
    public IReadOnlyList<TenantSource> Order { get; set; } =
        [TenantSource.Claim, TenantSource.Subdomain, TenantSource.Path, TenantSource.Header];

    /// <summary>The tenant header name.</summary>
    public string HeaderName { get; set; } = "X-Tenant";
}
