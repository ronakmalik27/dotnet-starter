namespace Starter.Platform.Events;

/// <summary>
/// Dispatcher tuning. Defaults are the doc-cited values (LLD 7.1); tests
/// shrink the timings, production overrides nothing without a doc change.
/// </summary>
public sealed class OutboxOptions
{
    /// <summary>Fast-lane poll period (LLD 7.1: 500 ms).</summary>
    public TimeSpan FastPollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Slow-lane poll period (LLD 7.1: 2 s).</summary>
    public TimeSpan SlowPollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Claim batch size (LLD 7.1: limit 100).</summary>
    public int BatchSize { get; init; } = 100;

    /// <summary>Attempts beyond this park the row (LLD 7.1: attempts &gt; 8).</summary>
    public int MaxAttempts { get; init; } = 8;

    /// <summary>
    /// Per-lane send timeout: the slowest consumer/provider timeout in that
    /// lane (PL-6). Part of the lease so an in-flight send can never be
    /// re-claimed.
    /// </summary>
    public TimeSpan FastSendTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan SlowSendTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Exponential backoff cap (LLD 7.1: min(2^attempts, 300) s).</summary>
    public TimeSpan MaxBackoff { get; init; } = TimeSpan.FromSeconds(300);

    /// <summary>Upper bound of the uniform jitter added to every lease.</summary>
    public TimeSpan MaxJitter { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Delivered rows older than this are purged; poisoned rows never are (doc 07 section 3).</summary>
    public TimeSpan DeliveredRetention { get; init; } = TimeSpan.FromDays(7);

    /// <summary>How often a non-leader instance re-tries to take the advisory lock.</summary>
    public TimeSpan LeaderRetryInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Postgres advisory lock key for dispatcher leadership: exactly one
    /// leader across ACA revisions during the deploy overlap (HLD 2.1).
    /// </summary>
    public long AdvisoryLockKey { get; init; } = 0x54_52_50_53_59_4F_42_58; // "TRPSYOBX"

    public TimeSpan SendTimeout(Lane lane) =>
        lane == Lane.Fast ? FastSendTimeout : SlowSendTimeout;

    public TimeSpan PollInterval(Lane lane) =>
        lane == Lane.Fast ? FastPollInterval : SlowPollInterval;
}
