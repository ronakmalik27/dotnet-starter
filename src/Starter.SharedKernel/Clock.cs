namespace Starter.SharedKernel;

/// <summary>
/// The only source of current time in Starter: DateTime.Now and
/// DateTimeOffset.UtcNow are banned outside the SharedKernel. A
/// fixed-surface wrapper over the .NET TimeProvider pattern: production
/// wires <see cref="TimeProvider.System"/>, tests wire a FakeTimeProvider
/// and advance it (tests own time).
/// </summary>
public sealed class Clock
{
    private readonly TimeProvider _timeProvider;

    public Clock(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// The wall clock. For composition roots only; everything else receives
    /// a Clock by injection.
    /// </summary>
    public static Clock System { get; } = new(TimeProvider.System);

    /// <summary>
    /// The current instant in UTC (storage time is UTC). Normalized
    /// here rather than trusted from the provider: TimeProvider.System
    /// already reports zero offset, but a fake seeded with an offset
    /// instant would otherwise leak that offset into storage paths.
    /// </summary>
    public DateTimeOffset UtcNow => _timeProvider.GetUtcNow().ToUniversalTime();

    /// <summary>The current calendar date in UTC.</summary>
    public DateOnly TodayUtc => DateOnly.FromDateTime(UtcNow.UtcDateTime);
}
