namespace Starter.Platform.Notifications;

/// <summary>
/// The email transport seam. Modules compose an <see cref="EmailMessage"/>
/// and hand it here; which concrete sender runs (console or SMTP) is a
/// composition-root choice bound from the Email:Provider config. Callers
/// never depend on the concrete transport.
/// </summary>
public interface IEmailSender
{
    /// <summary>Delivers one message. Throws when delivery fails.</summary>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}
