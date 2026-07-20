using Microsoft.Extensions.Logging;

namespace Starter.Platform.Notifications;

/// <summary>
/// The development-default transport: it does not touch the network, it
/// logs the whole message at Information so a developer can read and copy
/// anything inside it (a verification link, a one-time code) straight from
/// the console. This is also the transport the integration suite and a
/// local `dotnet run` use unless Email:Provider is switched to smtp.
/// </summary>
internal sealed class ConsoleEmailSender(ILogger<ConsoleEmailSender> logger) : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.To);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.Subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.TextBody);

        NotificationLog.ConsoleEmail(logger, message.To, message.Subject, message.TextBody);
        return Task.CompletedTask;
    }
}
