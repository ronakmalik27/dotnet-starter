using System.Net;
using System.Text.Json;

namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// The <c>ip_cidr</c> built-in (abac.md section 3): satisfied iff the request's
/// client IP is inside one of the <c>allow</c> CIDR ranges (IPv4 or IPv6). The
/// classic network-conditional-access rule (Okta / Entra "trusted network"): a
/// grant that only counts from a corporate egress range or a VPN CIDR, the natural
/// fit for a service-account key confined to a CI runner's IP range.
/// <para>
/// Payload: <c>{ "type": "ip_cidr", "allow": ["203.0.113.0/24", "2001:db8::/32"] }</c>.
/// Fail-closed if the client IP is unknown or unparseable, or if <c>allow</c> is
/// empty. Two obligations honored here: (a) an IPv4-mapped IPv6 address
/// (<c>::ffff:a.b.c.d</c>, which a dual-stack Kestrel listener reports for an IPv4
/// client) is normalized back to IPv4 before matching, else a plain IPv4 CIDR
/// never matches; (b) <see cref="Validate"/> bounds <c>allow</c> to
/// <see cref="MaxAllowEntries"/> so a pathological payload cannot bloat a grant row.
/// </para>
/// </summary>
public sealed class IpCidrConditionEvaluator : IConditionEvaluator
{
    /// <summary>The upper bound on <c>allow</c> entries a single grant may carry.</summary>
    public const int MaxAllowEntries = 64;

    public string ConditionType => "ip_cidr";

    public void Validate(JsonElement condition)
    {
        if (!condition.TryGetProperty("allow", out var allow) || allow.ValueKind != JsonValueKind.Array)
        {
            throw new ConditionFormatException("An ip_cidr condition requires an 'allow' array of CIDR ranges.");
        }

        var count = allow.GetArrayLength();
        if (count == 0)
        {
            throw new ConditionFormatException("An ip_cidr condition's 'allow' list must not be empty.");
        }

        if (count > MaxAllowEntries)
        {
            throw new ConditionFormatException(
                $"An ip_cidr condition's 'allow' list must have at most {MaxAllowEntries} entries.");
        }

        foreach (var entry in allow.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || !IPNetwork.TryParse(entry.GetString()!, out _))
            {
                throw new ConditionFormatException(
                    "Every ip_cidr 'allow' entry must be a valid CIDR range (e.g. 203.0.113.0/24).");
            }
        }
    }

    public bool IsSatisfied(JsonElement condition, RequestAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);

        // Fail closed on an unknown client IP: an ip_cidr grant behind an
        // unconfigured forwarded-headers setup locks callers out rather than leaks.
        if (attributes.ClientIp is not { } clientIp)
        {
            return false;
        }

        // Normalize an IPv4-mapped IPv6 address (::ffff:a.b.c.d) back to IPv4, else
        // a plain IPv4 CIDR never matches a dual-stack listener's reported address.
        if (clientIp.IsIPv4MappedToIPv6)
        {
            clientIp = clientIp.MapToIPv4();
        }

        if (!condition.TryGetProperty("allow", out var allow) || allow.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var entry in allow.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.String
                && IPNetwork.TryParse(entry.GetString()!, out var network)
                && network.BaseAddress.AddressFamily == clientIp.AddressFamily
                && network.Contains(clientIp))
            {
                return true;
            }
        }

        return false;
    }
}
