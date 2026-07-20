namespace Starter.Platform.Http;

/// <summary>The doc 08 section 1 idempotency header names.</summary>
public static class IdempotencyHeaders
{
    /// <summary>Client-generated UUIDv7 required on every mutating request (INV-4).</summary>
    public const string Key = "Idempotency-Key";

    /// <summary>"true" on responses replayed from the store rather than executed.</summary>
    public const string Replayed = "Idempotency-Replayed";
}
