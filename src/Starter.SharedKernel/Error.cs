namespace Starter.SharedKernel;

/// <summary>
/// A machine-readable expected failure. <see cref="Code"/> is a stable
/// dot-scoped slug ("sample.not_found") that survives message rewording;
/// <see cref="Message"/> is developer prose, not user-facing copy
/// (user-facing copy lives client-side).
/// </summary>
public sealed record Error
{
    public Error(ErrorKind kind, string code, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        Kind = kind;
        Code = code;
        Message = message;
    }

    public ErrorKind Kind { get; }

    public string Code { get; }

    public string Message { get; }
}
