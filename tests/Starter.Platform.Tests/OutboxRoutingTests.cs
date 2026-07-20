using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// Lane membership rule: one outbox row per lane that has a consumer for
/// the event type; no consumers, no outbox rows (the event still reaches
/// the domain_events spine).
/// </summary>
public class OutboxRoutingTests
{
    [Fact]
    public void Route_NoConsumers_YieldsNoLanes()
    {
        var writer = new OutboxWriter([]);

        writer.Route("sample.note.created").ShouldBeEmpty();
    }

    [Fact]
    public void Route_ConsumersOnBothLanes_YieldsBothLanesOnce()
    {
        var writer = new OutboxWriter(
        [
            new StubConsumer(Lane.Fast, "sample.note.created"),
            new StubConsumer(Lane.Fast, "sample.note.created"),
            new StubConsumer(Lane.Slow, "sample.note.created"),
        ]);

        writer.Route("sample.note.created").ShouldBe([Lane.Fast, Lane.Slow]);
    }

    [Fact]
    public void Route_UnsubscribedEventType_YieldsNoLanes()
    {
        var writer = new OutboxWriter([new StubConsumer(Lane.Fast, "sample.widget.created")]);

        writer.Route("sample.note.created").ShouldBeEmpty();
    }

    private sealed class StubConsumer(Lane lane, params string[] eventTypes) : IDomainEventConsumer
    {
        public Lane Lane { get; } = lane;

        public IReadOnlyCollection<string> EventTypes { get; } = eventTypes;

        public Task ConsumeAsync(DomainEventRecord domainEvent, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
