using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// Lane membership is doc 09's rule (LLD 7.1): one outbox row per lane
/// that has a consumer for the event type; no consumers, no outbox rows
/// (the event still reaches the domain_events spine).
/// </summary>
public class OutboxRoutingTests
{
    [Fact]
    public void Route_NoConsumers_YieldsNoLanes()
    {
        var writer = new OutboxWriter([]);

        writer.Route("money.expense.created").ShouldBeEmpty();
    }

    [Fact]
    public void Route_ConsumersOnBothLanes_YieldsBothLanesOnce()
    {
        var writer = new OutboxWriter(
        [
            new StubConsumer(Lane.Fast, "money.expense.created"),
            new StubConsumer(Lane.Fast, "money.expense.created"),
            new StubConsumer(Lane.Slow, "money.expense.created"),
        ]);

        writer.Route("money.expense.created").ShouldBe([Lane.Fast, Lane.Slow]);
    }

    [Fact]
    public void Route_UnsubscribedEventType_YieldsNoLanes()
    {
        var writer = new OutboxWriter([new StubConsumer(Lane.Fast, "trips.trip.created")]);

        writer.Route("money.expense.created").ShouldBeEmpty();
    }

    private sealed class StubConsumer(Lane lane, params string[] eventTypes) : IDomainEventConsumer
    {
        public Lane Lane { get; } = lane;

        public IReadOnlyCollection<string> EventTypes { get; } = eventTypes;

        public Task ConsumeAsync(DomainEventRecord domainEvent, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
