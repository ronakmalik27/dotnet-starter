namespace Starter.SharedKernel;

/// <summary>
/// The expected-failure channel for operations with no return value
/// (LLD section 1: handlers return Result; exceptions are for bugs, not
/// flow). Also carries the factories for <see cref="Result{T}"/>.
/// </summary>
public sealed class Result
{
    private static readonly Result CachedSuccess = new(null);

    private readonly Error? _error;

    private Result(Error? error) => _error = error;

    public bool IsSuccess => _error is null;

    public bool IsFailure => _error is not null;

    /// <summary>
    /// The failure. Throws on a success: reading an absent error is a bug.
    /// </summary>
    public Error Error =>
        _error ?? throw new InvalidOperationException("Result is a success; it carries no error.");

    public static Result Success() => CachedSuccess;

    public static Result Failure(Error error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result(error);
    }

    public static Result<T> Success<T>(T value) => Result<T>.CreateSuccess(value);

    public static Result<T> Failure<T>(Error error) => Result<T>.CreateFailure(error);

    public TOut Match<TOut>(Func<TOut> onSuccess, Func<Error, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);
        return IsSuccess ? onSuccess() : onFailure(Error);
    }
}
