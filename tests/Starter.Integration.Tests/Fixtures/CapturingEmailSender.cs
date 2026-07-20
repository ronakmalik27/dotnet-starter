using System.Collections.Concurrent;
using Starter.Platform.Notifications;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// Test double for <see cref="IEmailSender"/>: instead of sending, it
/// captures every message so a test can read the verification link and
/// token straight out of it. Thread-safe - the host may dispatch on any
/// request thread.
/// </summary>
public sealed class CapturingEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<EmailMessage> _sent = new();

    /// <summary>Every message captured so far, in send order.</summary>
    public IReadOnlyList<EmailMessage> Sent => _sent.ToArray();

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        _sent.Enqueue(message);
        return Task.CompletedTask;
    }

    /// <summary>Drops all captured messages (used to isolate a test's mailbox).</summary>
    public void Clear()
    {
        while (_sent.TryDequeue(out _))
        {
            // drain
        }
    }
}
