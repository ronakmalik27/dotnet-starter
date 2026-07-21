using Microsoft.Extensions.Options;

namespace Starter.Platform.Events;

/// <summary>
/// A custom IValidateOptions for the parts of <see cref="OutboxOptions"/> a
/// data annotation cannot express: the durations. [Range] guards the numeric
/// knobs (BatchSize, MaxAttempts), but a TimeSpan carries no such attribute,
/// so a zero or negative poll interval, send timeout, backoff cap, retention,
/// or leader-retry period would sail through and only surface as a wedged
/// dispatcher at runtime (a zero poll interval spins hot; a negative timeout
/// or lease makes every send look already-expired). This fails those fast at
/// startup (registered with ValidateOnStart) with a message naming the
/// offending field. The shipped defaults satisfy every rule.
/// </summary>
public sealed class OutboxOptionsValidator : IValidateOptions<OutboxOptions>
{
    public ValidateOptionsResult Validate(string? name, OutboxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();

        // Every lease/poll/timeout/retention duration must be strictly
        // positive: a zero or negative value has no sensible meaning and
        // would either spin the dispatcher or void every lease.
        RequirePositive(failures, nameof(options.FastPollInterval), options.FastPollInterval);
        RequirePositive(failures, nameof(options.SlowPollInterval), options.SlowPollInterval);
        RequirePositive(failures, nameof(options.FastSendTimeout), options.FastSendTimeout);
        RequirePositive(failures, nameof(options.SlowSendTimeout), options.SlowSendTimeout);
        RequirePositive(failures, nameof(options.MaxBackoff), options.MaxBackoff);
        RequirePositive(failures, nameof(options.DeliveredRetention), options.DeliveredRetention);
        RequirePositive(failures, nameof(options.LeaderRetryInterval), options.LeaderRetryInterval);

        // Jitter may be zero (disable jitter), but never negative: a negative
        // upper bound would make the uniform sample invalid.
        if (options.MaxJitter < TimeSpan.Zero)
        {
            failures.Add(
                $"Outbox:{nameof(options.MaxJitter)} must be greater than or equal to zero (it is the "
                + $"upper bound of the per-lease jitter); it was {options.MaxJitter}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void RequirePositive(List<string> failures, string field, TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
        {
            failures.Add($"Outbox:{field} must be greater than zero; it was {value}.");
        }
    }
}
