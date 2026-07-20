using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Starter.Platform.Notifications;

/// <summary>
/// The production transport over SMTP (MailKit). Builds a MIME message from
/// the <see cref="EmailMessage"/> and the configured From identity, connects
/// with STARTTLS when Email:Smtp:UseStartTls is set, authenticates when a
/// username and password are present (an unauthenticated relay is allowed
/// when they are not), sends, and disconnects cleanly.
/// </summary>
internal sealed class SmtpEmailSender(IOptions<EmailOptions> options) : IEmailSender
{
    private readonly EmailOptions _options = options.Value;

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.To);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.Subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.TextBody);

        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(_options.FromName, _options.FromAddress));
        mime.To.Add(MailboxAddress.Parse(message.To));
        mime.Subject = message.Subject;

        var body = new BodyBuilder { TextBody = message.TextBody };
        if (!string.IsNullOrWhiteSpace(message.HtmlBody))
        {
            body.HtmlBody = message.HtmlBody;
        }

        mime.Body = body.ToMessageBody();

        var smtp = _options.Smtp;
        var socketOptions = smtp.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.Auto;

        using var client = new SmtpClient();
        await client.ConnectAsync(smtp.Host, smtp.Port, socketOptions, cancellationToken);

        // Authenticate only when credentials are configured; an open relay
        // (submission host that trusts the network) needs no login.
        if (!string.IsNullOrEmpty(smtp.Username) && !string.IsNullOrEmpty(smtp.Password))
        {
            await client.AuthenticateAsync(smtp.Username, smtp.Password, cancellationToken);
        }

        await client.SendAsync(mime, cancellationToken);
        await client.DisconnectAsync(quit: true, cancellationToken);
    }
}
