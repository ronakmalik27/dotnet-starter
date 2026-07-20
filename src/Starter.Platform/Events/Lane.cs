namespace Starter.Platform.Events;

/// <summary>
/// Outbox dispatch lanes (LLD 7.1). Fast carries in-process consumers
/// (hub emits, chat system messages, in-app notification writes:
/// milliseconds per event); slow carries provider calls with timeouts
/// (email, web push). Stored as the doc 07 check-constrained text values.
/// </summary>
public enum Lane
{
    Fast,
    Slow,
}

/// <summary>The doc 07 check-constrained storage names.</summary>
internal static class LaneNames
{
    public const string Fast = "fast";
    public const string Slow = "slow";

    public static string Of(Lane lane) => lane == Lane.Fast ? Fast : Slow;
}
