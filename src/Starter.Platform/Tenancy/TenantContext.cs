namespace Starter.Platform.Tenancy;

/// <summary>
/// The mutable, scoped <see cref="ITenantContext"/> the middleware and the
/// outbox dispatcher set. Internal and its setters live inside the platform:
/// request code reads it through <see cref="ITenantContext"/>, never widens
/// it. One instance per scope, so a request and a consumer each carry their
/// own tenant with no cross-talk.
/// </summary>
internal sealed class TenantContext : ITenantContext
{
    public Guid TenantId { get; private set; }

    public string? Slug { get; private set; }

    public bool IsResolved { get; private set; }

    /// <summary>
    /// Establishes the tenant by id (the resolvable case): the GUC and query
    /// filter bind to this id. A non-empty id resolves; the empty id does not
    /// (fail-closed). <paramref name="slug"/> is carried for observability.
    /// </summary>
    public void Resolve(Guid tenantId, string? slug)
    {
        TenantId = tenantId;
        Slug = slug;
        IsResolved = tenantId != Guid.Empty;
    }

    /// <summary>
    /// Records a supplied slug that cannot be mapped to a tenant id yet (no
    /// tenants table until the Tenancy module): observability only, NOT
    /// resolved, so a slug-only request still fails closed at the endpoint.
    /// </summary>
    public void RecordUnmappedSlug(string slug)
    {
        Slug = slug;
        IsResolved = false;
    }

    /// <summary>
    /// The consumer-path bind: the dispatcher sets the tenant from an event's
    /// <c>tenant_id</c> before invoking a consumer. A null id (a platform-level
    /// event) leaves the context unresolved, so a platform consumer runs with
    /// no tenant GUC.
    /// </summary>
    public void BindConsumerTenant(Guid? tenantId)
    {
        if (tenantId is Guid id)
        {
            Resolve(id, slug: null);
        }
    }
}

/// <summary>
/// The immutable "no tenant" context: an unresolved <see cref="ITenantContext"/>
/// for the contexts that are never tenant-scoped - the design-time migration
/// factory and the outbox writer's platform-schema context (platform tables
/// carry no RLS). It can never resolve a tenant, so it can never set the GUC.
/// Reached across assemblies through <see cref="ITenantContext.None"/>.
/// </summary>
internal sealed class NoTenant : ITenantContext
{
    public static readonly NoTenant Instance = new();

    private NoTenant()
    {
    }

    public Guid TenantId => Guid.Empty;

    public string? Slug => null;

    public bool IsResolved => false;
}

/// <summary>
/// The immutable "this exact tenant" context, reached across assemblies through
/// <see cref="ITenantContext.ForTenant"/>. Unlike <see cref="TenantContext"/> it
/// has no setters, so a caller can bind a context to a fixed tenant but can
/// never re-point it. Used by the self-serve provisioner on the bypass path, so
/// the tenant it carries stamps the outbox events and the query filter without
/// touching the request-scoped context.
/// </summary>
internal sealed class FixedTenant(Guid tenantId) : ITenantContext
{
    public Guid TenantId { get; } = tenantId;

    public string? Slug => null;

    public bool IsResolved => TenantId != Guid.Empty;
}
