namespace Starter.SharedKernel;

/// <summary>
/// The single place UUID versioning lives: every id in the system is a
/// UUIDv7 minted here, so primary keys stay time-ordered and B-tree
/// friendly. Guid.NewGuid (v4) is banned outside the SharedKernel by the
/// architecture rules.
/// </summary>
public static class Ids
{
    /// <summary>Mints a UUIDv7 stamped with the current system time.</summary>
    public static Guid NewId() => Guid.CreateVersion7();

    /// <summary>
    /// Mints a UUIDv7 stamped with an explicit instant. This is the
    /// deterministic-time overload (tests own time).
    /// </summary>
    public static Guid NewId(DateTimeOffset timestamp) => Guid.CreateVersion7(timestamp);
}
