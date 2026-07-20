using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Starter.Platform.Notifications;

namespace Starter.Identity.PasswordReset;

/// <summary>
/// Composes and sends the password-reset message: formats the link from the
/// configured template (URL-encoding the raw token), builds a plain-text
/// <see cref="EmailMessage"/>, and hands it to the platform
/// <see cref="IEmailSender"/>. The raw token exists only in memory here (it
/// is never persisted or put on the domain_events spine) and reaches the
/// recipient solely through this link. Mirrors the verify-email composer.
/// </summary>
internal sealed class PasswordResetEmailComposer(
    IEmailSender emailSender,
    IOptions<PasswordResetEmailOptions> options,
    ILogger<PasswordResetEmailComposer> logger)
{
    private readonly PasswordResetEmailOptions _options = options.Value;

    public async Task SendPasswordResetEmailAsync(
        string emailAddress,
        string rawToken,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(emailAddress);
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);

        var link = _options.UrlTemplate.Replace(
            "{token}", Uri.EscapeDataString(rawToken), StringComparison.Ordinal);

        var message = new EmailMessage
        {
            To = emailAddress,
            Subject = "Reset your password",
            TextBody =
                "Reset your password by opening this link:\n\n"
                + link
                + "\n\nThe link expires in one hour. If you did not request a "
                + "password reset, you can ignore this message.",
        };

        PasswordResetEmailLog.Dispatching(logger);
        await emailSender.SendAsync(message, cancellationToken);
    }
}
