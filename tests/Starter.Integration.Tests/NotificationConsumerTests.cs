using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The first domain-event consumer proven end to end: a registration
/// reattempt (registering the same email twice) drives an
/// identity.registration.reattempted event through the outbox to the
/// notifications consumer, which sends exactly one "was this you?" notice to
/// the address - and only that notice, not a duplicate on the next poll. The
/// reusable dedup store's claim contract is proven directly: the first claim
/// of a (consumer, event) pair wins, every later claim loses.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class NotificationConsumerTests(StarterAppFixture fixture)
{
    private const string Password = "Starter-Notice-Passphrase-7g3k";
    private const string NoticeSubject = "Did you try to sign up?";

    [Fact]
    public async Task RegistrationReattempt_SendsExactlyOneWasThisYouNotice()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = $"reattempt-{Guid.NewGuid():N}@starter.example";

        // First register: creates the account and sends the verification
        // email (a different subject, so it never counts as a notice).
        var first = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/register", new { email, password = Password }, cancellationToken);
        first.EnsureSuccessStatusCode();

        // Second register with the same email: the reattempt. Same success,
        // and the "was this you?" notice rides the outbox to the consumer.
        var second = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/register", new { email, password = Password }, cancellationToken);
        second.EnsureSuccessStatusCode();

        // The notice arrives asynchronously (slow lane, 2 s poll). Wait for
        // the first, then let another poll cycle pass and confirm it was not
        // re-sent - the delivered row must not redeliver, and the consumer
        // must not double-send.
        await WaitForNoticeCountAsync(email, atLeast: 1, cancellationToken);
        await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);

        NoticeCount(email).ShouldBe(1);

        // Sanity: the reattempt did not re-send a verification email either.
        fixture.Emails.Sent
            .Count(message => message.To == email && message.Subject == "Verify your email")
            .ShouldBe(1);
    }

    [Fact]
    public async Task ProcessedEventStore_ClaimsAnEventOnce()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var store = fixture.Factory.Services.GetRequiredService<ProcessedEventStore>();
        const string consumer = "test.dedup.consumer";
        var eventId = Guid.NewGuid();

        // First claim wins; the second claim of the same pair loses.
        (await store.TryRecordAsync(consumer, eventId, cancellationToken)).ShouldBeTrue();
        (await store.TryRecordAsync(consumer, eventId, cancellationToken)).ShouldBeFalse();

        // A different event id is a fresh claim; a different consumer for the
        // same event id is independent and also wins.
        (await store.TryRecordAsync(consumer, Guid.NewGuid(), cancellationToken)).ShouldBeTrue();
        (await store.TryRecordAsync("other.consumer", eventId, cancellationToken)).ShouldBeTrue();
    }

    private int NoticeCount(string email) =>
        fixture.Emails.Sent.Count(message => message.To == email && message.Subject == NoticeSubject);

    private async Task WaitForNoticeCountAsync(string email, int atLeast, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (NoticeCount(email) >= atLeast)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException(
            $"Expected at least {atLeast} '{NoticeSubject}' notice(s) to {email} within the deadline.");
    }
}
