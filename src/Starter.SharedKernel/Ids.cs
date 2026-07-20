namespace Starter.SharedKernel;

/// <summary>
/// The single place UUID versioning lives (doc 13 section 2): every id in
/// the system is a UUIDv7 minted here, so primary keys stay time-ordered and
/// B-tree friendly (doc 07). Guid.NewGuid (v4) is banned outside the
/// SharedKernel by the doc 12 section 5 architecture rules.
/// </summary>
public static class Ids
{
    /// <summary>Mints a UUIDv7 stamped with the current system time.</summary>
    public static Guid NewId() => Guid.CreateVersion7();

    /// <summary>
    /// Mints a UUIDv7 stamped with an explicit instant. This is the
    /// deterministic-time overload (INV-6: tests own time).
    /// </summary>
    public static Guid NewId(DateTimeOffset timestamp) => Guid.CreateVersion7(timestamp);
}
