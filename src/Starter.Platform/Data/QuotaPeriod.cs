namespace Starter.Platform.Data;

/// <summary>
/// The metered-quota billing period (quotas.md section 3): the CALENDAR MONTH in
/// UTC. Pure functions over an injected instant (never <c>DateTime.UtcNow</c> - the
/// banned-API arch test forbids it), so a test can pin the clock and cross a period
/// boundary deterministically. A per-tenant billing anchor and rolling windows are
/// documented grow-into (section 9), not built.
/// </summary>
public static class QuotaPeriod
{
    /// <summary>
    /// The first of <paramref name="now"/>'s month at 00:00:00 UTC (a <c>date</c>).
    /// The lower bound of the window <c>[PeriodStart, ResetAt)</c> and the counter
    /// row's period key.
    /// </summary>
    public static DateOnly PeriodStart(DateTimeOffset now)
    {
        var utc = now.ToUniversalTime();
        return new DateOnly(utc.Year, utc.Month, 1);
    }

    /// <summary>
    /// The first of the NEXT month at 00:00:00 UTC. The upper bound of the window
    /// and the instant the metered counter resets. Rolls a December instant over
    /// into the next January (<see cref="DateOnly.AddMonths"/> handles the year).
    /// </summary>
    public static DateTimeOffset ResetAt(DateTimeOffset now)
    {
        var next = PeriodStart(now).AddMonths(1);
        return new DateTimeOffset(next.Year, next.Month, 1, 0, 0, 0, TimeSpan.Zero);
    }

    /// <summary>
    /// Whole seconds until <paramref name="resetAt"/> from <paramref name="now"/>,
    /// never negative (clamped at 0). The value the metered gate writes into the
    /// <c>Retry-After</c> header: a client backs off exactly to the period reset,
    /// and a clock already past the reset gets 0 (retry now).
    /// </summary>
    public static long RetryAfterSeconds(DateTimeOffset now, DateTimeOffset resetAt)
    {
        var seconds = Math.Ceiling((resetAt - now).TotalSeconds);
        return seconds <= 0 ? 0 : (long)seconds;
    }
}
