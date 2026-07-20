using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;

namespace Starter.Platform.Http;

/// <summary>
/// The LLD 7.2 idempotency filter (INV-4). Mutating endpoints opt in via
/// RequireIdempotency, positioned first in the endpoint filter chain
/// (LLD section 1: idempotency before authorization and validation).
///
/// Semantics: lookup (user, key) -> hit replays the stored status and body
/// with Idempotency-Replayed: true; miss executes the handler and stores
/// the response in the same transaction as the handler's writes (the
/// doc 07 table is in the same DB precisely so replay-after-crash is
/// consistent). Same key on a different endpoint is 422 (client bug,
/// surface it). An in-flight duplicate is 409 with Retry-After 1 s.
///
/// The in-flight guard is a transaction-scoped Postgres advisory lock on
/// (user, key), taken before the lookup: a racing duplicate either loses
/// the lock while the first request runs (409) or arrives after commit and
/// replays. The lock dies with the transaction, so a crashed request
/// releases it and leaves the key unconsumed - the retry re-executes.
/// The lock key is a 64-bit hash; a cross-pair collision yields a spurious,
/// self-healing 409 (odds ~2^-64 per pair - acceptable at our concurrency,
/// LLD 7.2's "simpler and honest").
///
/// Only 2xx responses are stored: a failed handler rolls the transaction
/// back, so there is no consistent same-transaction snapshot to store, and
/// the client may retry the same key after fixing the request. Replays
/// restore status and body only, never per-response headers such as
/// Location (LLD 7.2 contract: status, body, plus the replay marker).
/// </summary>
public sealed class IdempotencyFilter(
    NpgsqlDataSource dataSource,
    PlatformHttpMetrics metrics,
    IOptions<JsonOptions> jsonOptions,
    ILogger<IdempotencyFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var cancellationToken = http.RequestAborted;
        var endpointName = EndpointName(http);

        // The filter sits after authentication (LLD section 1); reaching it
        // without a caller identity is a pipeline wiring bug, surfaced as
        // the 401 the missing middleware would have sent.
        var userId = AuthenticatedUserId(http.User);
        if (userId is null)
        {
            IdempotencyLog.MissingUser(logger, endpointName);
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        if (!TryReadKey(http.Request, out var key, out var keyError))
        {
            return TypedResults.Problem(StarterProblems.Validation(
                http,
                new Dictionary<string, string[]> { [IdempotencyHeaders.Key] = [keyError] }));
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        if (!await TryAcquireInFlightLockAsync(connection, transaction, userId.Value, key, cancellationToken))
        {
            IdempotencyLog.InFlightRejected(logger, endpointName, key);
            metrics.InFlightRejected();
            http.Response.Headers.RetryAfter = "1";
            return TypedResults.Problem(StarterProblems.IdempotencyInFlight(http));
        }

        var stored = await LookupAsync(connection, transaction, userId.Value, key, cancellationToken);
        if (stored is not null)
        {
            if (!string.Equals(stored.Endpoint, endpointName, StringComparison.Ordinal))
            {
                IdempotencyLog.EndpointMismatch(logger, key, stored.Endpoint, endpointName);
                metrics.EndpointMismatch();
                return TypedResults.Problem(StarterProblems.Validation(
                    http,
                    new Dictionary<string, string[]>
                    {
                        [IdempotencyHeaders.Key] =
                            ["This idempotency key was already used for a different endpoint; keys are minted per request (doc 08 section 1)."],
                    }));
            }

            IdempotencyLog.Replayed(logger, endpointName, key);
            metrics.Replayed();
            return new ReplayedIdempotentResult(stored.ResponseCode, stored.ResponseBody);
        }

        http.Features.Set<IIdempotentTransaction>(new IdempotentTransaction(connection, transaction));
        object? result;
        try
        {
            result = await next(context);
        }
        finally
        {
            http.Features.Set<IIdempotentTransaction>(null);
        }

        // Status first, body only for stored outcomes: a non-2xx result
        // passes through untouched even when its body is not snapshotable.
        if (IdempotentResponseSnapshot.StatusOf(result) is >= 200 and < 300)
        {
            var (statusCode, responseBody) =
                IdempotentResponseSnapshot.Capture(result, jsonOptions.Value.SerializerOptions);
            await StoreAsync(
                connection, transaction, userId.Value, key, endpointName,
                statusCode, responseBody, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            metrics.Stored();
        }

        // Non-2xx: the await-using rollback discards the handler's staged
        // writes and the key stays unconsumed for a corrected retry.
        return result;
    }

    private static Guid? AuthenticatedUserId(ClaimsPrincipal user)
    {
        var value = user.FindFirstValue("sub") ?? user.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    private static bool TryReadKey(HttpRequest request, out Guid key, out string error)
    {
        key = default;
        var values = request.Headers[IdempotencyHeaders.Key];
        if (values.Count == 0)
        {
            error = "The Idempotency-Key header is required on mutating endpoints (doc 08 section 1).";
            return false;
        }

        if (values.Count > 1 || !Guid.TryParse(values[0], out key))
        {
            error = "The Idempotency-Key header must be a single UUID.";
            return false;
        }

        if (key.Version != 7)
        {
            error = "The Idempotency-Key must be a UUIDv7 (doc 08 section 1).";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static string EndpointName(HttpContext http)
    {
        // The route template, not the concrete path: LLD 7.2 scopes keys to
        // the endpoint, and "/trips/{id}" is one endpoint across all ids.
        var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;
        return $"{http.Request.Method} {pattern ?? http.Request.Path.Value ?? "/"}";
    }

    private static async Task<bool> TryAcquireInFlightLockAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid userId,
        Guid key,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "select pg_try_advisory_xact_lock(hashtextextended($1, 0))", connection, transaction)
        {
            Parameters = { new() { Value = $"idempotency:{userId:N}:{key:N}" } },
        };
        return (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task<StoredResponse?> LookupAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid userId,
        Guid key,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            select endpoint, response_code, response_body::text
            from platform.idempotency_keys
            where user_id = $1 and key = $2
            """,
            connection,
            transaction)
        {
            Parameters =
            {
                new() { Value = userId },
                new() { Value = key },
            },
        };

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new StoredResponse(
            reader.GetString(0),
            reader.GetInt32(1),
            reader.GetString(2));
    }

    private static async Task StoreAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid userId,
        Guid key,
        string endpoint,
        int responseCode,
        string responseBody,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            insert into platform.idempotency_keys
              (user_id, key, endpoint, response_code, response_body)
            values ($1, $2, $3, $4, $5)
            """,
            connection,
            transaction)
        {
            Parameters =
            {
                new() { Value = userId },
                new() { Value = key },
                new() { Value = endpoint },
                new() { Value = responseCode },
                new() { Value = responseBody, NpgsqlDbType = NpgsqlDbType.Jsonb },
            },
        };
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private sealed record StoredResponse(string Endpoint, int ResponseCode, string ResponseBody);
}

/// <summary>Endpoint opt-in for the idempotency filter (LLD 7.2).</summary>
public static class IdempotencyEndpointExtensions
{
    /// <summary>
    /// Requires an Idempotency-Key on this endpoint. Call it before any
    /// other filter so idempotency stays first in the chain (LLD section 1:
    /// idempotency before authorization and validation).
    /// </summary>
    public static TBuilder RequireIdempotency<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder =>
        builder.AddEndpointFilter<TBuilder, IdempotencyFilter>();
}
