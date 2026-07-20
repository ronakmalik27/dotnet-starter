using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Starter.SharedKernel;

namespace Starter.Platform.Http;

/// <summary>
/// Turns a handler's return value into the (status, jsonb body) pair the
/// idempotency store persists (LLD 7.2). Supported shapes are the ones a
/// doc 08 mutation endpoint may produce: JSON value results (Ok, Created),
/// status-only results (NoContent), typed unions (Results&lt;T1,..,Tn&gt;,
/// classified by the concrete result they carry), and plain objects
/// (implicit 200). Anything else under RequireIdempotency is a developer
/// bug and throws - the problem mapper turns that into a 500, and the
/// transaction rollback keeps the key unconsumed.
/// </summary>
internal static class IdempotentResponseSnapshot
{
    /// <summary>
    /// The status alone, computed without touching the body: the filter
    /// checks it first so a non-2xx result passes through untouched even
    /// when its body could never be captured.
    /// </summary>
    public static int StatusOf(object? result) => Unwrap(result) switch
    {
        IStatusCodeHttpResult statusResult => statusResult.StatusCode ?? StatusCodes.Status200OK,
        _ => StatusCodes.Status200OK,
    };

    public static (int StatusCode, string BodyJson) Capture(
        object? result,
        JsonSerializerOptions serializerOptions)
    {
        result = Unwrap(result);
        switch (result)
        {
            case null:
                return (StatusCodes.Status200OK, ReplayedIdempotentResult.EmptyBody);
            case string:
                throw new InvalidOperationException(
                    "String results are written as text/plain and cannot be replayed as JSON; return a typed JSON result (doc 08 section 1: JSON everywhere).");
            case Result:
                throw new InvalidOperationException(
                    "Map Result failures to an IResult (ErrorResultExtensions.ToProblemResult) before returning (LLD section 1).");
            case IValueHttpResult valueResult:
                {
                    var status = (result as IStatusCodeHttpResult)?.StatusCode ?? StatusCodes.Status200OK;
                    var body = valueResult.Value is null
                        ? ReplayedIdempotentResult.EmptyBody
                        : JsonSerializer.Serialize(valueResult.Value, valueResult.Value.GetType(), serializerOptions);
                    return (status, body);
                }

            case IContentTypeHttpResult:
                // Must precede IStatusCodeHttpResult: content results
                // (TypedResults.Text, Results.Content) implement the status
                // interface too and would otherwise be captured as an empty
                // body and silently replayed (issue #170).
                throw new InvalidOperationException(
                    "Content results are written as text/csv/html and cannot be replayed as JSON; return a typed JSON result (doc 08 section 1: JSON everywhere).");
            case IStatusCodeHttpResult statusOnly:
                return (statusOnly.StatusCode ?? StatusCodes.Status200OK, ReplayedIdempotentResult.EmptyBody);
            case IResult:
                throw new InvalidOperationException(
                    $"Result type {result.GetType().Name} cannot be captured for idempotent replay; return a JSON value result, a status-only result, or a plain object.");
            default:
                if (IsResultOfT(result.GetType()))
                {
                    throw new InvalidOperationException(
                        "Map Result<T> to an IResult (success value or ErrorResultExtensions.ToProblemResult) before returning (LLD section 1).");
                }

                return (
                    StatusCodes.Status200OK,
                    JsonSerializer.Serialize(result, result.GetType(), serializerOptions));
        }
    }

    /// <summary>
    /// The typed-union endpoint idiom (Results&lt;T1,..,Tn&gt;) implements
    /// INestedHttpResult and neither IStatusCodeHttpResult nor
    /// IValueHttpResult: classifying the union itself would misreport
    /// every branch as an implicit 200 and fail the capture. Classify the
    /// concrete result it carries instead (looped: unions nest).
    /// </summary>
    private static object? Unwrap(object? result)
    {
        while (result is INestedHttpResult nested)
        {
            result = nested.Result;
        }

        return result;
    }

    private static bool IsResultOfT(Type type) =>
        type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Result<>);
}
