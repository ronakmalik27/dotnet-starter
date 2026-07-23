using System.Globalization;
using System.Text.Json;

namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// The <c>time_of_day</c> built-in (abac.md section 3): satisfied iff the request
/// time falls within the <c>[startUtc, endUtc)</c> window (both <c>HH:mm</c>, UTC).
/// Wrap-around past midnight is supported (<c>startUtc</c> &gt; <c>endUtc</c> means
/// the window spans midnight). The "business-hours only" rule.
/// <para>
/// Payload: <c>{ "type": "time_of_day", "startUtc": "09:00", "endUtc": "17:00" }</c>.
/// It reads <see cref="RequestAttributes.Now"/>, which the gate stamps from the
/// injected <c>Clock</c> (never <c>DateTimeOffset.UtcNow</c> - the BannedApi arch
/// test forbids it), so this is the kind that deliberately exercises the mockable
/// time path.
/// </para>
/// </summary>
public sealed class TimeOfDayConditionEvaluator : IConditionEvaluator
{
    // HH:mm, 24-hour, invariant so the separator is a plain colon regardless of
    // the host culture.
    private const string TimeFormat = "HH\\:mm";

    public string ConditionType => "time_of_day";

    public void Validate(JsonElement condition)
    {
        if (!TryReadTime(condition, "startUtc", out _) || !TryReadTime(condition, "endUtc", out _))
        {
            throw new ConditionFormatException(
                "A time_of_day condition requires 'startUtc' and 'endUtc' as HH:mm UTC times (e.g. 09:00).");
        }
    }

    public bool IsSatisfied(JsonElement condition, RequestAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);

        if (!TryReadTime(condition, "startUtc", out var start) || !TryReadTime(condition, "endUtc", out var end))
        {
            return false;
        }

        var now = TimeOnly.FromDateTime(attributes.Now.UtcDateTime);

        // [start, end): the ordinary case is a same-day window; start > end is a
        // window that wraps past midnight (e.g. 22:00 -> 06:00).
        return start <= end
            ? now >= start && now < end
            : now >= start || now < end;
    }

    private static bool TryReadTime(JsonElement condition, string property, out TimeOnly value)
    {
        value = default;
        return condition.TryGetProperty(property, out var element)
            && element.ValueKind == JsonValueKind.String
            && TimeOnly.TryParseExact(
                element.GetString(), TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out value);
    }
}
