namespace Starter.Platform.Notifications;

/// <summary>The email transports the template ships with.</summary>
public enum EmailProvider
{
    /// <summary>Logs the message via ILogger. The development default.</summary>
    Console = 0,

    /// <summary>Sends over SMTP (MailKit). The production transport.</summary>
    Smtp = 1,
}

/// <summary>
/// Email settings, bound from the Email section. The default provider is
/// the console transport, so a fresh host sends nothing to the network and
/// a developer reads the message (including any verification link) straight
/// from the logs. Switch Provider to smtp and fill Smtp for real delivery.
/// The SMTP password lives only in its designated home (dotnet user-secrets
/// locally, a managed secret store in production) - never a default here.
/// </summary>
public sealed class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary>Which transport to register. Defaults to the console sender.</summary>
    public EmailProvider Provider { get; set; } = EmailProvider.Console;

    /// <summary>The From address stamped on every message.</summary>
    public string FromAddress { get; set; } = "no-reply@starter.example";

    /// <summary>The From display name stamped on every message.</summary>
    public string FromName { get; set; } = "Starter";

    /// <summary>SMTP connection settings; used only when Provider is smtp.</summary>
    public SmtpOptions Smtp { get; set; } = new();
}

/// <summary>SMTP connection settings for the smtp provider.</summary>
public sealed class SmtpOptions
{
    /// <summary>The SMTP server host.</summary>
    public string Host { get; set; } = "localhost";

    /// <summary>The SMTP submission port (587 is the STARTTLS default).</summary>
    public int Port { get; set; } = 587;

    /// <summary>The SMTP username; null or empty means send unauthenticated.</summary>
    public string? Username { get; set; }

    /// <summary>
    /// The SMTP password. Comes from config or a secret store, never a
    /// default. Only used when Username is set.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>Upgrade the connection with STARTTLS. On by default.</summary>
    public bool UseStartTls { get; set; } = true;
}
