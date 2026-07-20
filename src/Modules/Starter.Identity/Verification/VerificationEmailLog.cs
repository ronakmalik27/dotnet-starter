using Microsoft.Extensions.Logging;

namespace Starter.Identity.Verification;

/// <summary>
/// Source-generated log messages for verification-email dispatch (CA1848).
/// No PII: the recipient address and the raw token never appear here (the
/// console transport is the one place the full message, link included, is
/// logged for local development).
/// </summary>
internal static partial class VerificationEmailLog
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "Handing a verification email to the email transport.")]
    public static partial void Dispatching(ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Verification email dispatch failed; the account exists and the resend endpoint can retry.")]
    public static partial void DispatchFailed(ILogger logger, Exception exception);
}
