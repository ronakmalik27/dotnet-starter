using Npgsql;

namespace Starter.Platform.Http;

/// <summary>
/// The open transaction the idempotency filter exposes to the handler via
/// HttpContext.Features. Handler writes ride this transaction (a DbContext
/// enlists via the OutboxWriter pattern: shared connection + UseTransaction),
/// and the filter appends the idempotency row and commits after the handler
/// succeeds - so the stored response and the handler's writes are atomic
/// (the shared transaction is why replay-after-crash is
/// consistent).
/// </summary>
public interface IIdempotentTransaction
{
    NpgsqlConnection Connection { get; }

    NpgsqlTransaction Transaction { get; }
}

internal sealed record IdempotentTransaction(
    NpgsqlConnection Connection,
    NpgsqlTransaction Transaction) : IIdempotentTransaction;
