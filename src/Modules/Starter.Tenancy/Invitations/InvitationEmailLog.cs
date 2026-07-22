using Microsoft.Extensions.Logging;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// Source-generated log messages for invitation email dispatch (CA1848). No
/// PII: the recipient address and the raw token never appear here (the console
/// transport is the one place the full message, link included, is logged for
/// local development).
/// </summary>
internal static partial class InvitationEmailLog
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "Handing an invitation email to the email transport.")]
    public static partial void Dispatching(ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Invitation email dispatch failed; the invitation exists and an admin can re-invite.")]
    public static partial void DispatchFailed(ILogger logger, Exception exception);
}
