using System.Diagnostics.Metrics;

namespace Starter.Platform.Http;

/// <summary>
/// Platform HTTP plumbing observability (story #17 DoD). Rate and duration
/// of the RED trio ride ASP.NET Core's built-in http.server.request.duration
/// metric (tagged with status); these counters add the error detail the
/// built-ins cannot see: idempotency outcomes and exceptions mapped to 500s.
/// Standard .NET Meter, so the OTel exporter story wires up later without
/// touching this type (same contract as OutboxMetrics).
/// </summary>
public sealed class PlatformHttpMetrics : IDisposable
{
    public const string MeterName = "Starter.Platform.Http";

    private readonly Meter _meter;
    private readonly Counter<long> _replays;
    private readonly Counter<long> _inFlightRejections;
    private readonly Counter<long> _endpointMismatches;
    private readonly Counter<long> _storedResponses;
    private readonly Counter<long> _unhandledExceptions;

    public PlatformHttpMetrics()
    {
        _meter = new Meter(MeterName);
        _replays = _meter.CreateCounter<long>("idempotency.replays");
        _inFlightRejections = _meter.CreateCounter<long>("idempotency.in_flight_rejections");
        _endpointMismatches = _meter.CreateCounter<long>("idempotency.endpoint_mismatches");
        _storedResponses = _meter.CreateCounter<long>("idempotency.stored_responses");
        _unhandledExceptions = _meter.CreateCounter<long>("problems.unhandled_exceptions");
    }

    public void Replayed() => _replays.Add(1);

    public void InFlightRejected() => _inFlightRejections.Add(1);

    public void EndpointMismatch() => _endpointMismatches.Add(1);

    public void Stored() => _storedResponses.Add(1);

    public void UnhandledExceptionMapped() => _unhandledExceptions.Add(1);

    public void Dispose() => _meter.Dispose();
}
