using Microsoft.Extensions.Logging;

namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// Source-generated log messages for the tenancy control plane (CA1848). No
/// PII: the email address and the raw verification token never appear here.
/// </summary>
internal static partial class TenancyLog
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Self-serve verification email dispatch failed; the tenant and owner exist and the owner can verify via the resend endpoint.")]
    public static partial void VerificationEmailFailed(ILogger logger, Exception exception);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Self-serve auto-login failed ({Code}) after provisioning; the tenant and owner exist and the owner can log in normally.")]
    public static partial void AutoLoginFailed(ILogger logger, string code);
}
