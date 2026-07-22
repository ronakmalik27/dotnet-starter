using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Starter.Platform.Notifications;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// Composes and sends the invitation message: formats the accept link from the
/// configured template (URL-encoding the raw token), builds a plain-text
/// <see cref="EmailMessage"/>, and hands it to the platform
/// <see cref="IEmailSender"/>. The raw token exists only in memory here (it is
/// never persisted or put on the domain_events spine) and reaches the invitee
/// solely through this link. Mirrors the verify-email and password-reset
/// composers in Identity.
/// </summary>
internal sealed class InvitationEmailComposer(
    IEmailSender emailSender,
    IOptions<InvitationEmailOptions> options,
    ILogger<InvitationEmailComposer> logger)
{
    private readonly InvitationEmailOptions _options = options.Value;

    public async Task SendInvitationEmailAsync(
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
            Subject = "You have been invited to a workspace",
            TextBody =
                "You have been invited to join a workspace. Accept the invitation by "
                + "opening this link:\n\n"
                + link
                + "\n\nThe link expires in seven days. If you were not expecting this "
                + "invitation, you can ignore this message.",
        };

        InvitationEmailLog.Dispatching(logger);
        await emailSender.SendAsync(message, cancellationToken);
    }
}
