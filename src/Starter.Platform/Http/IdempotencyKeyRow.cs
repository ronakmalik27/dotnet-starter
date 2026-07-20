namespace Starter.Platform.Http;

/// <summary>
/// A row of platform.idempotency_keys (doc 07 section 3, INV-4): the stored
/// response for a (user, key) pair, written in the same transaction as the
/// handler's writes and replayed on retries. Purged after 14 days
/// (doc 07 section 13).
/// </summary>
public sealed class IdempotencyKeyRow
{
    public required Guid UserId { get; init; }

    public required Guid Key { get; init; }

    /// <summary>Method + route template ("POST /api/v1/trips"); LLD 7.2 key scope.</summary>
    public required string Endpoint { get; init; }

    public required int ResponseCode { get; init; }

    /// <summary>The stored JSON body; JSON null for body-less responses.</summary>
    public required string ResponseBody { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
}
