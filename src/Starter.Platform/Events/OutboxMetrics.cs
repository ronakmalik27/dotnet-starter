using System.Diagnostics.Metrics;

namespace Starter.Platform.Events;

/// <summary>
/// Dispatcher observability (story #16 DoD; GA-3/GA-7 signals, doc 11
/// section 7): dispatch lag and poison counts. Standard .NET Meter, so the
/// OTel exporter story wires up later without touching this type.
/// </summary>
public sealed class OutboxMetrics : IDisposable
{
    public const string MeterName = "Starter.Platform.Outbox";

    private readonly Meter _meter;
    private readonly Counter<long> _dispatched;
    private readonly Counter<long> _failed;
    private readonly Counter<long> _poisoned;
    private readonly Counter<long> _unroutable;
    private readonly Histogram<double> _lagSeconds;

    public OutboxMetrics()
    {
        _meter = new Meter(MeterName);
        _dispatched = _meter.CreateCounter<long>("outbox.dispatched");
        _failed = _meter.CreateCounter<long>("outbox.send_failures");
        _poisoned = _meter.CreateCounter<long>("outbox.poisoned");
        _unroutable = _meter.CreateCounter<long>("outbox.unroutable");
        _lagSeconds = _meter.CreateHistogram<double>("outbox.dispatch_lag_seconds");
    }

    public void Dispatched(Lane lane, TimeSpan lag)
    {
        var tag = LaneTag(lane);
        _dispatched.Add(1, tag);
        _lagSeconds.Record(lag.TotalSeconds, tag);
    }

    public void SendFailed(Lane lane) => _failed.Add(1, LaneTag(lane));

    public void Poisoned(Lane lane) => _poisoned.Add(1, LaneTag(lane));

    public void Unroutable(Lane lane) => _unroutable.Add(1, LaneTag(lane));

    public void Dispose() => _meter.Dispose();

    private static KeyValuePair<string, object?> LaneTag(Lane lane) =>
        new("lane", lane == Lane.Fast ? "fast" : "slow");
}
