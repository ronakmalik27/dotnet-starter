namespace Starter.Platform.Notifications;

/// <summary>
/// One outbound email. Plain text is required; HTML is optional and, when
/// present, rides alongside the text part as a multipart/alternative body.
/// The transport (see <see cref="IEmailSender"/>) decides how it is
/// delivered - logged to the console in development, sent over SMTP in
/// production.
/// </summary>
public sealed record EmailMessage
{
    /// <summary>The recipient address.</summary>
    public required string To { get; init; }

    /// <summary>The subject line.</summary>
    public required string Subject { get; init; }

    /// <summary>The plain-text body. Always present, even when HtmlBody is set.</summary>
    public required string TextBody { get; init; }

    /// <summary>Optional HTML body; null for text-only mail.</summary>
    public string? HtmlBody { get; init; }
}
