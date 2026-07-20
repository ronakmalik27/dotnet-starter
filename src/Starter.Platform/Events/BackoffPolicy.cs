namespace Starter.Platform.Events;

/// <summary>
/// The lease arithmetic (LLD 7.1, PL-6): a lease is
/// send_timeout(lane) + min(2^attempts, cap) + jitter. It is armed twice
/// per claim cycle: once for every row inside the claim transaction (so a
/// leader that dies right after claiming leaves rows that redeliver
/// promptly), and again per row on the leadership session immediately
/// before that row's send (so the lease always covers the send window it
/// guards, however deep in the batch the row sat). The pre-send re-arm is
/// the PL-6 anchor: it succeeds only while the advisory lock is held, so
/// a row whose send may still be in flight can never be re-claimed - by
/// this leader or a failed-over one.
/// </summary>
internal static class BackoffPolicy
{
    /// <summary>
    /// Lease duration for a row that has been attempted
    /// <paramref name="attemptsBeforeClaim"/> times already (the LLD
    /// formula uses the pre-increment attempt count).
    /// </summary>
    public static TimeSpan Lease(OutboxOptions options, Lane lane, int attemptsBeforeClaim, double jitterSample)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(attemptsBeforeClaim);
        if (jitterSample is < 0 or >= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(jitterSample), jitterSample, "Jitter sample must be in [0, 1).");
        }

        var backoffSeconds = Math.Min(
            Math.Pow(2, attemptsBeforeClaim),
            options.MaxBackoff.TotalSeconds);

        return options.SendTimeout(lane)
            + TimeSpan.FromSeconds(backoffSeconds)
            + (options.MaxJitter * jitterSample);
    }
}
