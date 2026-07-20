namespace Starter.Platform.Http;

/// <summary>
/// A row of platform.idempotency_keys: the stored
/// response for a (user, key) pair, written in the same transaction as the
/// handler's writes and replayed on retries. Purged after 14 days.
/// </summary>
public sealed class IdempotencyKeyRow
{
    public required Guid UserId { get; init; }

    public required Guid Key { get; init; }

    /// <summary>Method + route template ("POST /api/v1/items"); the idempotency key scope.</summary>
    public required string Endpoint { get; init; }

    public required int ResponseCode { get; init; }

    /// <summary>The stored JSON body; JSON null for body-less responses.</summary>
    public required string ResponseBody { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
}
