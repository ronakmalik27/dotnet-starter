using System.Net;
using System.Net.Sockets;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The SSRF address classifier (webhooks.md section 6). Rejects using the IANA
/// IPv4/IPv6 special-purpose registries (not an ad-hoc subset). Before range-checking,
/// an IPv4-mapped IPv6 address (<c>::ffff:0:0/96</c>) is unwrapped, and NAT64
/// (<c>64:ff9b::/96</c>), 6to4 (<c>2002::/16</c>), and Teredo (<c>2001::/32</c>) have
/// their embedded IPv4 extracted and re-checked - otherwise an AAAA answer sails past an
/// IPv4-only check. A bare <see cref="IPAddress.IsLoopback"/> is insufficient (it misses
/// <c>0.0.0.0</c>), so this checks explicit CIDRs.
/// </summary>
internal static class WebhookAddressGuard
{
    /// <summary>
    /// True when <paramref name="address"/> is a blocked (non-public) delivery target.
    /// <paramref name="allowLoopback"/> is false in production (loopback is blocked like
    /// every other special-purpose range); the integration suite sets it true only so
    /// the worker can reach a test-local loopback receiver, and it relaxes NOTHING else.
    /// </summary>
    public static bool IsBlocked(IPAddress address, bool allowLoopback = false)
    {
        ArgumentNullException.ThrowIfNull(address);

        var normalized = Unwrap(address);
        return normalized.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsBlockedV4(normalized.GetAddressBytes(), allowLoopback),
            AddressFamily.InterNetworkV6 => IsBlockedV6(normalized.GetAddressBytes(), allowLoopback),
            // An address family that is neither IPv4 nor IPv6 is never a legitimate
            // public HTTP target: fail closed.
            _ => true,
        };
    }

    /// <summary>
    /// Reduces an IPv6 address that carries an embedded IPv4 (mapped, NAT64, 6to4, or
    /// Teredo) to that IPv4 so the IPv4 blocklist applies; every other address is
    /// returned unchanged.
    /// </summary>
    private static IPAddress Unwrap(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();

        // NAT64 well-known prefix 64:ff9b::/96 - the last 32 bits are the IPv4.
        if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0
            && bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0)
        {
            return new IPAddress(bytes[12..16]);
        }

        // 6to4 2002::/16 - the embedded IPv4 is bytes 2..6.
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            return new IPAddress(bytes[2..6]);
        }

        // Teredo 2001:0000::/32 - the client IPv4 is the last 32 bits, each byte XOR 0xFF.
        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x00)
        {
            var client = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                client[i] = (byte)(bytes[12 + i] ^ 0xFF);
            }

            return new IPAddress(client);
        }

        return address;
    }

    private static bool IsBlockedV4(byte[] b, bool allowLoopback)
    {
        // 127.0.0.0/8 loopback: blocked unless the caller opts in (tests only).
        if (b[0] == 127)
        {
            return !allowLoopback;
        }

        return b[0] == 0                                       // 0.0.0.0/8 "this network"
            || b[0] == 10                                      // 10.0.0.0/8 private
            || (b[0] == 100 && (b[1] & 0xC0) == 0x40)          // 100.64.0.0/10 CGNAT
            || (b[0] == 169 && b[1] == 254)                    // 169.254.0.0/16 link-local (incl. metadata 169.254.169.254)
            || (b[0] == 172 && (b[1] & 0xF0) == 0x10)          // 172.16.0.0/12 private
            || (b[0] == 192 && b[1] == 0 && b[2] == 0)         // 192.0.0.0/24 IETF protocol assignments
            || (b[0] == 192 && b[1] == 0 && b[2] == 2)         // 192.0.2.0/24 TEST-NET-1
            || (b[0] == 192 && b[1] == 168)                    // 192.168.0.0/16 private
            || (b[0] == 198 && (b[1] == 18 || b[1] == 19))     // 198.18.0.0/15 benchmarking
            || (b[0] == 198 && b[1] == 51 && b[2] == 100)      // 198.51.100.0/24 TEST-NET-2
            || (b[0] == 203 && b[1] == 0 && b[2] == 113)       // 203.0.113.0/24 TEST-NET-3
            || (b[0] & 0xF0) == 0xE0                            // 224.0.0.0/4 multicast
            || (b[0] & 0xF0) == 0xF0;                           // 240.0.0.0/4 reserved (incl. 255.255.255.255)
    }

    private static bool IsBlockedV6(byte[] b, bool allowLoopback)
    {
        // ::1/128 loopback: blocked unless the caller opts in (tests only).
        if (IsUnspecifiedOrLoopback(b, out var loopback))
        {
            return !(loopback && allowLoopback);
        }

        return (b[0] & 0xFE) == 0xFC                            // fc00::/7 unique-local
            || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)          // fe80::/10 link-local
            || b[0] == 0xFF;                                    // ff00::/8 multicast
    }

    private static bool IsUnspecifiedOrLoopback(byte[] b, out bool loopback)
    {
        loopback = false;
        for (var i = 0; i < 15; i++)
        {
            if (b[i] != 0)
            {
                return false;
            }
        }

        // First 15 bytes are zero: ::/128 (unspecified, last byte 0) or ::1 (loopback).
        loopback = b[15] == 1;
        return b[15] == 0 || b[15] == 1;
    }
}
