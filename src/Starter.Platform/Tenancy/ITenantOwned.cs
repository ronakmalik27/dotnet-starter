namespace Starter.Platform.Tenancy;

/// <summary>
/// The marker for a tenant-owned entity: its rows belong to exactly one
/// tenant and are never visible across the boundary. A module's DbContext
/// applies the tenant query filter to every <see cref="ITenantOwned"/> entity
/// (ergonomics) and a matching Postgres row-level-security policy enforces it
/// in the database (the authority). Writes stamp <see cref="TenantId"/> from
/// the ambient <see cref="ITenantContext"/>, never from client input.
/// </summary>
public interface ITenantOwned
{
    /// <summary>The owning tenant. Set from <see cref="ITenantContext"/> on write.</summary>
    Guid TenantId { get; }
}
