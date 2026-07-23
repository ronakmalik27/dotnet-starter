using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Starter.Identity.Domain;
using Starter.Platform.Events;
using Starter.Platform.Notifications;

namespace Starter.Identity.Notifications;

/// <summary>
/// The first domain-event consumer: the account-security notices. It sends a
/// "was this you?" notice on a registration reattempt and a "your password
/// changed" notice on a password change. Slow lane - a notice is an email
/// provider call.
/// <para>
/// Delivery semantics: AT-MOST-ONCE, deduped by a processed_events claim.
/// A notice is a NON-transactional side effect (the email leaves the
/// process), so exactly-once is impossible; the honest, terminating choice
/// for a non-critical notice is claim-then-send-best-effort:
/// </para>
/// <list type="number">
///   <item>Claim the event with <see cref="ProcessedEventStore"/> BEFORE
///   sending. The claim is atomic, so a redelivery of an already-handled
///   event sees the claim already taken and returns without sending - no
///   double notice on every redelivery.</item>
///   <item>On a first claim, send best-effort. If the send throws, the
///   claim is already committed, so it is NOT redelivered: that one notice
///   is dropped and logged. Dropping a non-critical notice beats
///   redelivering it forever.</item>
/// </list>
/// A delivery-CRITICAL consumer would not use this shape: it would make its
/// side effect transactional (or idempotent downstream) and record the
/// claim only after the effect durably succeeded. This consumer is the
/// starter-appropriate example for a best-effort notice, not for a payment
/// or an audit write.
/// <para>
/// Singleton, per the <see cref="IDomainEventConsumer"/> contract: it resolves
/// the scoped <see cref="IdentityDbContext"/> from the dispatcher's per-consume
/// scope and never holds one on a field. Identity events are platform-level
/// (users are global, so the event's tenant is null and the scope carries no
/// tenant), and the users table is not tenant-owned, so its reads need no
/// tenant GUC.
/// </para>
/// </summary>
internal sealed class IdentityNotificationsConsumer(
    ProcessedEventStore processedEvents,
    IEmailSender emailSender,
    ILogger<IdentityNotificationsConsumer> logger) : IDomainEventConsumer
{
    /// <summary>The stable claim name for this consumer in processed_events.</summary>
    private const string ConsumerName = "identity.notifications";

    public Lane Lane => Lane.Slow;

    public IReadOnlyCollection<string> EventTypes { get; } =
    [
        "identity.registration.reattempted",
        "identity.password.changed",
        "identity.mfa.enabled",
        "identity.mfa.disabled",
    ];

    public async Task ConsumeAsync(
        IServiceProvider services,
        DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(domainEvent);

        // Both subscribed events set EntityId = the user id. Resolve the
        // scoped context from the dispatcher's scope (never a constructor
        // field, never a scope of our own).
        var db = services.GetRequiredService<IdentityDbContext>();

        var email = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == domainEvent.EntityId)
            .Select(user => user.Email)
            .SingleOrDefaultAsync(cancellationToken);
        if (email is null)
        {
            // The account is gone: nothing to notify. Not a failure - do not
            // redeliver. (No claim is taken, but a vanished user never
            // reappears, so redelivery would only re-hit this same branch.)
            IdentityNotificationsLog.UserGone(logger, domainEvent.EventType);
            return;
        }

        // Claim BEFORE sending. A redelivery of an already-handled event
        // sees the claim taken and returns here without re-sending.
        var claimed = await processedEvents.TryRecordAsync(ConsumerName, domainEvent.Id, cancellationToken);
        if (!claimed)
        {
            return;
        }

        var message = Compose(domainEvent.EventType, email);
        if (message is null)
        {
            // A lane/type the dispatcher routed here but this consumer does
            // not compose for - unreachable through EventTypes, but the
            // claim is committed, so treat it as handled and stop.
            return;
        }

        try
        {
            await emailSender.SendAsync(message, cancellationToken);
        }
        catch (Exception exception)
        {
            // The claim is committed, so the row will not redeliver. Drop
            // the one notice and log it: a security notice is not worth
            // infinite redelivery.
            IdentityNotificationsLog.SendFailed(logger, exception, domainEvent.Id, domainEvent.EventType);
        }
    }

    private static EmailMessage? Compose(string eventType, string emailAddress) => eventType switch
    {
        "identity.registration.reattempted" => new EmailMessage
        {
            To = emailAddress,
            Subject = "Did you try to sign up?",
            TextBody =
                "Someone tried to register with your email. If this was you, you "
                + "already have an account - sign in or reset your password. If not, "
                + "you can ignore this message.",
        },
        "identity.password.changed" => new EmailMessage
        {
            To = emailAddress,
            Subject = "Your password was changed",
            TextBody =
                "Your password was just changed. If this was not you, reset it "
                + "immediately or contact support.",
        },
        "identity.mfa.enabled" => new EmailMessage
        {
            To = emailAddress,
            Subject = "Two-factor authentication was enabled",
            TextBody =
                "Two-factor authentication was just enabled on your account. If this "
                + "was not you, reset your password immediately and contact support.",
        },
        "identity.mfa.disabled" => new EmailMessage
        {
            To = emailAddress,
            Subject = "Two-factor authentication was disabled",
            TextBody =
                "Two-factor authentication was just disabled on your account. If this "
                + "was not you, reset your password immediately and contact support.",
        },
        _ => null,
    };
}
