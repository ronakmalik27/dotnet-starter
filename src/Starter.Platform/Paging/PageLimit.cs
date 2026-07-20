namespace Starter.Platform.Paging;

/// <summary>
/// The keyset page-size contract modules share: an unspecified limit (null)
/// falls back to <see cref="Default"/>; a specified one is clamped into
/// [<see cref="Min"/>, <see cref="Max"/>], so no caller can request an
/// unbounded page and no query runs with a zero or negative take. Endpoints
/// pass the raw query value straight through here.
/// </summary>
public static class PageLimit
{
    /// <summary>The page size used when the caller specifies none.</summary>
    public const int Default = 20;

    /// <summary>The smallest page a caller may request.</summary>
    public const int Min = 1;

    /// <summary>The largest page a caller may request.</summary>
    public const int Max = 100;

    /// <summary>
    /// Resolves a caller-supplied limit: null becomes <see cref="Default"/>,
    /// anything else is clamped to [<see cref="Min"/>, <see cref="Max"/>].
    /// </summary>
    public static int Clamp(int? limit) =>
        limit is null ? Default : Math.Clamp(limit.Value, Min, Max);
}
