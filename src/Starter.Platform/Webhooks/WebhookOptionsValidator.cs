using Microsoft.Extensions.Options;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The duration-bounds validator for <see cref="WebhookOptions"/>: a data annotation
/// cannot express a positive TimeSpan, so a zero or negative poll interval, send
/// timeout, backoff cap, retention, or leader-retry period would sail through and only
/// surface as a wedged worker at runtime. This fails those fast at startup (registered
/// with ValidateOnStart) with a message naming the offending field. The shipped
/// defaults satisfy every rule. Mirrors <c>OutboxOptionsValidator</c>.
/// </summary>
public sealed class WebhookOptionsValidator : IValidateOptions<WebhookOptions>
{
    public ValidateOptionsResult Validate(string? name, WebhookOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();

        RequirePositive(failures, nameof(options.PollInterval), options.PollInterval);
        RequirePositive(failures, nameof(options.SendTimeout), options.SendTimeout);
        RequirePositive(failures, nameof(options.MaxBackoff), options.MaxBackoff);
        RequirePositive(failures, nameof(options.DeliveredRetention), options.DeliveredRetention);
        RequirePositive(failures, nameof(options.LeaderRetryInterval), options.LeaderRetryInterval);

        // Jitter may be zero (disable jitter), but never negative.
        if (options.MaxJitter < TimeSpan.Zero)
        {
            failures.Add(
                $"Webhooks:{nameof(options.MaxJitter)} must be greater than or equal to zero (it is the "
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
            failures.Add($"Webhooks:{field} must be greater than zero; it was {value}.");
        }
    }
}
