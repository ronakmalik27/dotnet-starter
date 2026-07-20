namespace Starter.SharedKernel;

/// <summary>
/// The expected-failure channel for operations that produce a value.
/// Create instances through <see cref="Result.Success{T}"/>
/// and <see cref="Result.Failure{T}"/> or the implicit conversions.
/// </summary>
public sealed class Result<T>
{
    private readonly T? _value;
    private readonly Error? _error;

    private Result(T? value, Error? error)
    {
        _value = value;
        _error = error;
    }

    public bool IsSuccess => _error is null;

    public bool IsFailure => _error is not null;

    /// <summary>
    /// The success value. Throws on a failure: reading an absent value is a
    /// bug - check <see cref="IsSuccess"/> or use <see cref="Match{TOut}"/>.
    /// </summary>
    public T Value =>
        IsSuccess
            ? _value!
            : throw new InvalidOperationException(
                $"Result is a failure ({_error!.Code}); it carries no value.");

    /// <summary>
    /// The failure. Throws on a success: reading an absent error is a bug.
    /// </summary>
    public Error Error =>
        _error ?? throw new InvalidOperationException("Result is a success; it carries no error.");

    public static implicit operator Result<T>(T value) => CreateSuccess(value);

    public static implicit operator Result<T>(Error error) => CreateFailure(error);

    public TOut Match<TOut>(Func<T, TOut> onSuccess, Func<Error, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);
        return IsSuccess ? onSuccess(_value!) : onFailure(Error);
    }

    internal static Result<T> CreateSuccess(T value) => new(value, null);

    internal static Result<T> CreateFailure(Error error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result<T>(default, error);
    }
}
