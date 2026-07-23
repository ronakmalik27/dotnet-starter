using Starter.Platform.Dsar;

namespace Starter.Sample.Dsar;

/// <summary>
/// The Sample module's erasure declaration (data-export-and-erasure.md section 4): the
/// tenant-owned sample tables, the read model (<c>note_index</c>) before its source
/// (<c>notes</c>). Both key on <c>tenant_id</c>. Declaration only - this touches no
/// bypass, so the module stays clean under the bypass-containment arch test.
/// </summary>
internal sealed class SampleErasureContributor : ITenantErasureContributor
{
    public IReadOnlyList<TenantTable> Tables { get; } =
    [
        new("sample.note_index", "tenant_id"),
        new("sample.notes", "tenant_id"),
    ];
}
