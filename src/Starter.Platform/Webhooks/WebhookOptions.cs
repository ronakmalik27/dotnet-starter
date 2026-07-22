using System.ComponentModel.DataAnnotations;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Delivery-worker and register-time tuning (webhooks.md sections 4, 6, 7a). Defaults
/// are the documented production values; tests shrink the timings. The numeric bounds
/// are data annotations enforced at startup (ValidateOnStart); the duration bounds are
/// a custom validator (<see cref="WebhookOptionsValidator"/>). The shipped defaults
/// satisfy every rule.
/// </summary>
public sealed class WebhookOptions
{
    /// <summary>The configuration section this binds from.</summary>
    public const string SectionName = "Webhooks";

    /// <summary>
    /// Postgres advisory lock key for delivery-worker leadership. DISTINCT from the
    /// outbox dispatcher's key (webhooks.md section 4) so the two leaders are elected
    /// independently: packed ASCII "WHOOKLCK".
    /// </summary>
    public long AdvisoryLockKey { get; init; } = 0x57_48_4F_4F_4B_4C_43_4B; // "WHOOKLCK"

    /// <summary>How often the worker polls for claimable deliveries.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Claim batch size.</summary>
    [Range(1, 500)]
    public int BatchSize { get; init; } = 100;

    /// <summary>Attempts beyond this dead-letter the delivery (webhooks.md section 4).</summary>
    [Range(1, 100)]
    public int MaxAttempts { get; init; } = 8;

    /// <summary>Exponential backoff cap: the retry push is <c>min(2^attempts, MaxBackoff) + jitter</c>.</summary>
    public TimeSpan MaxBackoff { get; init; } = TimeSpan.FromSeconds(300);

    /// <summary>Upper bound of the uniform jitter added to every backoff/lease.</summary>
    public TimeSpan MaxJitter { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Per-send HTTP timeout; bounds a single stuck endpoint (webhooks.md section 7a).</summary>
    public TimeSpan SendTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How often a non-leader instance re-tries to take the advisory lock.</summary>
    public TimeSpan LeaderRetryInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Delivered delivery rows older than this are purged; dead rows never are (webhooks.md section 9).</summary>
    public TimeSpan DeliveredRetention { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The cap on endpoints per tenant, bounding a single event's fan-out (webhooks.md section 7a).</summary>
    [Range(1, 1000)]
    public int MaxEndpointsPerTenant { get; init; } = 50;

    /// <summary>
    /// When true, the SSRF classifier permits loopback (127.0.0.0/8, ::1) delivery
    /// targets. Default FALSE (production blocks loopback with every other
    /// special-purpose range, webhooks.md section 6). This exists only so the
    /// integration suite can point the worker at a test-local loopback receiver; it
    /// never relaxes any other blocked range (metadata, private, link-local stay
    /// blocked regardless).
    /// </summary>
    public bool AllowLoopbackDelivery { get; init; }
}
