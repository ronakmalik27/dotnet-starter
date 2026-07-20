using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Starter.Platform.Notifications;

namespace Starter.Identity.Verification;

/// <summary>
/// Composes and sends the verify-email message: formats the link from the
/// configured template (URL-encoding the raw token), builds a plain-text
/// <see cref="EmailMessage"/>, and hands it to the platform
/// <see cref="IEmailSender"/>. The raw token exists only in memory here (it
/// is never persisted or put on the domain_events spine) and reaches the
/// recipient solely through this link.
/// </summary>
internal sealed class VerificationEmailComposer(
    IEmailSender emailSender,
    IOptions<VerificationEmailOptions> options,
    ILogger<VerificationEmailComposer> logger)
{
    private readonly VerificationEmailOptions _options = options.Value;

    public async Task SendVerificationEmailAsync(
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
            Subject = "Verify your email",
            TextBody =
                "Confirm your email address by opening this link:\n\n"
                + link
                + "\n\nIf you did not create an account, you can ignore this message.",
        };

        VerificationEmailLog.Dispatching(logger);
        await emailSender.SendAsync(message, cancellationToken);
    }
}
