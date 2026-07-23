using System.Net;
using System.Text.Json;
using Shouldly;
using Starter.Platform.Auth.Conditions;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The ABAC built-in evaluators and the dispatching registry as DB-free unit tests
/// (abac.md sections 3, 4, 7): the pure IP-CIDR and time-of-day logic (IPv4-mapped
/// normalization, the allow-list bound, the wrap-around-midnight window) and the
/// registry's fail-closed CHECK path (unknown type, malformed JSON, an evaluator
/// that throws all deny) plus its strict GRANT path (Validate throws and returns
/// the parsed type). RequestAttributes are built directly with a fixed instant and
/// client IP, so no clock or database is needed.
/// </summary>
public class ConditionEvaluatorTests
{
    private static readonly DateTimeOffset Noon = new(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

    private static RequestAttributes Attributes(IPAddress? clientIp, DateTimeOffset? now = null) => new()
    {
        Now = now ?? Noon,
        ClientIp = clientIp,
    };

    private static JsonElement Element(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    // --- ip_cidr -----------------------------------------------------------

    [Fact]
    public void IpCidr_Validate_AcceptsIpv4AndIpv6Ranges()
    {
        var evaluator = new IpCidrConditionEvaluator();

        Should.NotThrow(() => evaluator.Validate(
            Element("""{ "type": "ip_cidr", "allow": ["203.0.113.0/24", "2001:db8::/32"] }""")));
    }

    [Fact]
    public void IpCidr_Validate_RejectsMissingOrEmptyAllow()
    {
        var evaluator = new IpCidrConditionEvaluator();

        Should.Throw<ConditionFormatException>(() => evaluator.Validate(Element("""{ "type": "ip_cidr" }""")));
        Should.Throw<ConditionFormatException>(() => evaluator.Validate(
            Element("""{ "type": "ip_cidr", "allow": [] }""")));
    }

    [Fact]
    public void IpCidr_Validate_RejectsABadCidrEntry()
    {
        var evaluator = new IpCidrConditionEvaluator();

        Should.Throw<ConditionFormatException>(() => evaluator.Validate(
            Element("""{ "type": "ip_cidr", "allow": ["not-a-cidr"] }""")));
    }

    [Fact]
    public void IpCidr_Validate_RejectsAnOversizedAllowList()
    {
        var evaluator = new IpCidrConditionEvaluator();
        var entries = string.Join(",", Enumerable.Range(0, IpCidrConditionEvaluator.MaxAllowEntries + 1)
            .Select(i => $"\"10.{i / 256}.{i % 256}.0/24\""));

        Should.Throw<ConditionFormatException>(() => evaluator.Validate(
            Element($$"""{ "type": "ip_cidr", "allow": [{{entries}}] }""")));
    }

    [Fact]
    public void IpCidr_IsSatisfied_TrueWhenIpv4InRange_FalseWhenOut()
    {
        var evaluator = new IpCidrConditionEvaluator();
        var condition = Element("""{ "type": "ip_cidr", "allow": ["203.0.113.0/24"] }""");

        evaluator.IsSatisfied(condition, Attributes(IPAddress.Parse("203.0.113.5"))).ShouldBeTrue();
        evaluator.IsSatisfied(condition, Attributes(IPAddress.Parse("198.51.100.5"))).ShouldBeFalse();
    }

    [Fact]
    public void IpCidr_IsSatisfied_NormalizesIpv4MappedIpv6BeforeMatchingAnIpv4Cidr()
    {
        var evaluator = new IpCidrConditionEvaluator();
        var condition = Element("""{ "type": "ip_cidr", "allow": ["203.0.113.0/24"] }""");

        // A dual-stack listener reports ::ffff:203.0.113.5 for an IPv4 client; it
        // must be normalized to IPv4 or the plain IPv4 CIDR never matches.
        var mapped = IPAddress.Parse("203.0.113.5").MapToIPv6();
        mapped.IsIPv4MappedToIPv6.ShouldBeTrue();

        evaluator.IsSatisfied(condition, Attributes(mapped)).ShouldBeTrue();
    }

    [Fact]
    public void IpCidr_IsSatisfied_TrueForAnIpv6RangeMatch()
    {
        var evaluator = new IpCidrConditionEvaluator();
        var condition = Element("""{ "type": "ip_cidr", "allow": ["2001:db8::/32"] }""");

        evaluator.IsSatisfied(condition, Attributes(IPAddress.Parse("2001:db8::1"))).ShouldBeTrue();
        evaluator.IsSatisfied(condition, Attributes(IPAddress.Parse("2001:dead::1"))).ShouldBeFalse();
    }

    [Fact]
    public void IpCidr_IsSatisfied_FalseWhenClientIpIsUnknown()
    {
        var evaluator = new IpCidrConditionEvaluator();
        var condition = Element("""{ "type": "ip_cidr", "allow": ["203.0.113.0/24"] }""");

        evaluator.IsSatisfied(condition, Attributes(clientIp: null)).ShouldBeFalse();
    }

    // --- time_of_day -------------------------------------------------------

    [Fact]
    public void TimeOfDay_Validate_RejectsMissingOrMalformedTimes()
    {
        var evaluator = new TimeOfDayConditionEvaluator();

        Should.Throw<ConditionFormatException>(() => evaluator.Validate(
            Element("""{ "type": "time_of_day", "startUtc": "09:00" }""")));
        Should.Throw<ConditionFormatException>(() => evaluator.Validate(
            Element("""{ "type": "time_of_day", "startUtc": "9am", "endUtc": "17:00" }""")));
    }

    [Fact]
    public void TimeOfDay_IsSatisfied_InsideAndOutsideASameDayWindow()
    {
        var evaluator = new TimeOfDayConditionEvaluator();
        var condition = Element("""{ "type": "time_of_day", "startUtc": "09:00", "endUtc": "17:00" }""");

        var inside = new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);
        var before = new DateTimeOffset(2026, 7, 23, 8, 59, 0, TimeSpan.Zero);
        var atEnd = new DateTimeOffset(2026, 7, 23, 17, 0, 0, TimeSpan.Zero);

        evaluator.IsSatisfied(condition, Attributes(null, inside)).ShouldBeTrue();
        evaluator.IsSatisfied(condition, Attributes(null, before)).ShouldBeFalse();
        // End is exclusive: [start, end).
        evaluator.IsSatisfied(condition, Attributes(null, atEnd)).ShouldBeFalse();
    }

    [Fact]
    public void TimeOfDay_IsSatisfied_HandlesAWindowThatWrapsPastMidnight()
    {
        var evaluator = new TimeOfDayConditionEvaluator();
        var condition = Element("""{ "type": "time_of_day", "startUtc": "22:00", "endUtc": "06:00" }""");

        var lateNight = new DateTimeOffset(2026, 7, 23, 23, 30, 0, TimeSpan.Zero);
        var earlyMorning = new DateTimeOffset(2026, 7, 23, 5, 0, 0, TimeSpan.Zero);
        var midday = new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

        evaluator.IsSatisfied(condition, Attributes(null, lateNight)).ShouldBeTrue();
        evaluator.IsSatisfied(condition, Attributes(null, earlyMorning)).ShouldBeTrue();
        evaluator.IsSatisfied(condition, Attributes(null, midday)).ShouldBeFalse();
    }

    // --- registry ----------------------------------------------------------

    private static ConditionEvaluatorRegistry BuiltInRegistry() =>
        new([new IpCidrConditionEvaluator(), new TimeOfDayConditionEvaluator()]);

    [Fact]
    public void Registry_Validate_ReturnsTheParsedTypeForAValidCondition()
    {
        var registry = BuiltInRegistry();

        registry.Validate("""{ "type": "ip_cidr", "allow": ["203.0.113.0/24"] }""").ShouldBe("ip_cidr");
        registry.Validate("""{ "type": "time_of_day", "startUtc": "09:00", "endUtc": "17:00" }""")
            .ShouldBe("time_of_day");
    }

    [Fact]
    public void Registry_Validate_ThrowsOnUnknownTypeMissingTypeOrMalformedJson()
    {
        var registry = BuiltInRegistry();

        Should.Throw<ConditionFormatException>(() => registry.Validate("""{ "type": "cedar" }"""));
        Should.Throw<ConditionFormatException>(() => registry.Validate("""{ "allow": ["203.0.113.0/24"] }"""));
        Should.Throw<ConditionFormatException>(() => registry.Validate("not json"));
    }

    [Fact]
    public void Registry_IsSatisfied_FailsClosedOnUnknownTypeAndMalformedJson()
    {
        var registry = BuiltInRegistry();
        var attributes = Attributes(IPAddress.Parse("203.0.113.5"));

        registry.IsSatisfied("""{ "type": "cedar", "policyId": "x" }""", attributes).ShouldBeFalse();
        registry.IsSatisfied("not json", attributes).ShouldBeFalse();
        registry.IsSatisfied("""{ "allow": ["203.0.113.0/24"] }""", attributes).ShouldBeFalse();
    }

    [Fact]
    public void Registry_IsSatisfied_TrueForASatisfiedBuiltIn()
    {
        var registry = BuiltInRegistry();

        registry.IsSatisfied(
            """{ "type": "ip_cidr", "allow": ["203.0.113.0/24"] }""",
            Attributes(IPAddress.Parse("203.0.113.5"))).ShouldBeTrue();
    }

    [Fact]
    public void Registry_IsSatisfied_FailsClosedWhenAnEvaluatorThrows()
    {
        // A pluggable evaluator that throws at CHECK time must be caught and denied
        // (abac.md section 7): a security condition that cannot be evaluated must
        // never widen access.
        var registry = new ConditionEvaluatorRegistry([new ThrowingEvaluator()]);

        registry.IsSatisfied("""{ "type": "boom" }""", Attributes(IPAddress.Parse("203.0.113.5")))
            .ShouldBeFalse();
    }

    private sealed class ThrowingEvaluator : IConditionEvaluator
    {
        public string ConditionType => "boom";

        public void Validate(JsonElement condition) { }

        public bool IsSatisfied(JsonElement condition, RequestAttributes attributes) =>
            throw new InvalidOperationException("evaluator failure");
    }
}
