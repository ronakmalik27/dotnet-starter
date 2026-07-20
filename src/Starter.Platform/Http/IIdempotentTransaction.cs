using Npgsql;

namespace Starter.Platform.Http;

/// <summary>
/// The open transaction the idempotency filter exposes to the handler via
/// HttpContext.Features. Handler writes ride this transaction (a DbContext
/// enlists via the OutboxWriter pattern: shared connection + UseTransaction),
/// and the filter appends the idempotency row and commits after the handler
/// succeeds - so the stored response and the handler's writes are atomic
/// (LLD 7.2, doc 07 section 3: same DB precisely so replay-after-crash is
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
