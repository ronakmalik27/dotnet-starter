namespace Starter.Platform.Tenancy;

/// <summary>
/// The active tenant for a unit of work, request-scoped (set by
/// <see cref="TenantResolutionMiddleware"/>) or consumer-scoped (set by the
/// outbox dispatcher from an event's tenant). It is the single value the
/// transaction-start interceptor reads to issue
/// <c>set_config('app.current_tenant', ...)</c> and the EF query filter reads
/// to scope tenant-owned reads. Read-only by contract: nothing outside the
/// platform can flip the active tenant, so there is no in-band way to widen a
/// caller's reach.
/// </summary>
public interface ITenantContext
{
    /// <summary>
    /// The active tenant id, or <see cref="System.Guid.Empty"/> when no tenant
    /// is resolved. Fail-closed: an unresolved tenant leaves the GUC unset and
    /// the query filter comparing against the empty id, so a query with no
    /// tenant matches zero rows rather than leaking.
    /// </summary>
    Guid TenantId { get; }

    /// <summary>
    /// The tenant slug when one was supplied (subdomain or path), carried for
    /// observability. A slug alone does not resolve a tenant this increment:
    /// mapping a slug to an id needs the tenants table, which arrives with the
    /// Tenancy module.
    /// </summary>
    string? Slug { get; }

    /// <summary>
    /// True once a concrete tenant id is established. A tenant-scoped endpoint
    /// reached with this false answers 400 <c>starter:tenant-required</c>.
    /// </summary>
    bool IsResolved { get; }

    /// <summary>
    /// The immutable no-tenant context: never resolves a tenant, so it can
    /// never set the RLS GUC. Reachable across assemblies for the contexts that
    /// are never tenant-scoped by construction - the Identity registration-
    /// staging seam builds its context with this so a staged UserRegistered is
    /// stamped tenant_id = null (a global event). Exposing it widens nothing: it
    /// can only ever be the empty, unresolved tenant.
    /// </summary>
    static ITenantContext None => NoTenant.Instance;

    /// <summary>
    /// An immutable context resolved to a specific tenant, for the control-plane
    /// paths that run on the bypass data source and must stamp a known tenant on
    /// their writes and events (self-serve provisioning binds the new tenant so
    /// its TenantCreated / MembershipCreated events carry tenant_id = the new
    /// tenant). It runs on the BYPASSRLS role, so the GUC it sets is not an
    /// enforcement boundary; it exists only to carry the tenant to the outbox
    /// writer and the query filter. A request-scoped path never uses this - it
    /// takes the scoped <see cref="TenantContext"/> the middleware sets.
    /// </summary>
    static ITenantContext ForTenant(Guid tenantId) => new FixedTenant(tenantId);
}
