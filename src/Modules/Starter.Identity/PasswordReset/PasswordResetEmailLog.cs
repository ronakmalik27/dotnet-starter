using Microsoft.Extensions.Logging;

namespace Starter.Identity.PasswordReset;

/// <summary>
/// Source-generated log messages for password-reset email dispatch
/// (CA1848). No PII: the recipient address and the raw token never appear
/// here (the console transport is the one place the full message, link
/// included, is logged for local development).
/// </summary>
internal static partial class PasswordResetEmailLog
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "Handing a password-reset email to the email transport.")]
    public static partial void Dispatching(ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Password-reset email dispatch failed; a later forgot-password request re-mints a token.")]
    public static partial void DispatchFailed(ILogger logger, Exception exception);
}
