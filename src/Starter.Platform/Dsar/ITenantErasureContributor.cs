namespace Starter.Platform.Dsar;

/// <summary>
/// A module's DECLARATION of the tenant-owned tables the erasure service purges for
/// it (data-export-and-erasure.md section 4, GDPR Art. 17). A module declares only -
/// it never touches the bypass path itself, so <c>Sample</c> and <c>Identity</c>
/// stay clean under the bypass-containment arch test. <see cref="ITenantErasureService"/>
/// (Platform) executes the deletes on the bypass connection.
/// <para>
/// Tables are listed in FK-safe delete order (children before parents). Cross-CONTRIBUTOR
/// order follows DI registration and is not FK-safe by construction; it is safe today
/// because no foreign key crosses a module boundary, and <c>tenancy.tenants</c> (whose
/// own <c>id</c> is the discriminator) is declared LAST in the last-registered module.
/// </para>
/// </summary>
public interface ITenantErasureContributor
{
    /// <summary>The module's tenant-owned tables, schema-qualified, in FK-safe delete order.</summary>
    IReadOnlyList<TenantTable> Tables { get; }
}

/// <summary>
/// One tenant-owned table and the column that carries the tenant id
/// (data-export-and-erasure.md section 4). Nearly every table keys on
/// <c>tenant_id</c>; <c>tenancy.tenants</c> is the sole exception, keyed on its own
/// <c>id</c>. Both names come only from trusted code-side declarations, never client
/// input, so their interpolation into SQL is safe; the tenant id is always a bound
/// parameter.
/// </summary>
public sealed record TenantTable(string Table, string KeyColumn);
