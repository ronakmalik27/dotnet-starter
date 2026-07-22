using System.Net;
using Shouldly;
using Starter.Platform.Webhooks;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The SSRF address classifier (webhooks.md section 6): every blocked IANA range,
/// the IPv4-mapped / NAT64 / 6to4 / Teredo unwrap, and public addresses passing. The
/// production default blocks loopback with every other special-purpose range; the
/// loopback-allowed flag relaxes ONLY loopback.
/// </summary>
public class WebhookAddressGuardTests
{
    public static TheoryData<string> BlockedByDefault => new()
    {
        // IPv4 special-purpose ranges.
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",          // CGNAT
        "100.127.255.255",
        "127.0.0.1",           // loopback (blocked by default)
        "169.254.1.1",         // link-local
        "169.254.169.254",     // cloud metadata endpoint
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.10",          // TEST-NET-1
        "192.168.1.1",
        "198.18.0.1",          // benchmarking
        "198.19.255.255",
        "198.51.100.7",        // TEST-NET-2
        "203.0.113.9",         // TEST-NET-3
        "224.0.0.1",           // multicast
        "239.255.255.255",
        "240.0.0.1",           // reserved
        "255.255.255.255",     // limited broadcast
        // IPv6 special-purpose ranges.
        "::",                  // unspecified
        "::1",                 // loopback (blocked by default)
        "fc00::1",             // unique-local
        "fd12:3456::1",
        "fe80::1",             // link-local
        "ff02::1",             // multicast
        // Embedded-IPv4 wrappers around a private target.
        "::ffff:10.0.0.1",           // IPv4-mapped
        "::ffff:169.254.169.254",    // IPv4-mapped metadata
        "64:ff9b::a00:1",            // NAT64 -> 10.0.0.1
        "2002:a00:1::",              // 6to4 -> 10.0.0.1
        "2001:0:4136:e378:8000:63bf:f5ff:fffe", // Teredo -> client 10.0.0.1 (last 32 bits XOR 0xff)
    };

    public static TheoryData<string> PublicAddresses => new()
    {
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "172.32.0.1",                // just outside 172.16/12
        "100.128.0.1",               // just outside 100.64/10
        "192.1.0.1",                 // not 192.0.0/24
        "2606:2800:220:1:248:1893:25c8:1946",
        "2001:4860:4860::8888",      // Google DNS v6 (2001:4860, not Teredo 2001:0000)
        "::ffff:8.8.8.8",            // IPv4-mapped public
        "64:ff9b::808:808",          // NAT64 -> 8.8.8.8
        "2002:808:808::",            // 6to4 -> 8.8.8.8
        "2001:0:4136:e378:8000:63bf:f7f7:f7f7", // Teredo -> client 8.8.8.8
    };

    [Theory]
    [MemberData(nameof(BlockedByDefault))]
    public void IsBlocked_ProductionDefault_BlocksEverySpecialPurposeRange(string address)
    {
        WebhookAddressGuard.IsBlocked(IPAddress.Parse(address)).ShouldBeTrue(
            $"{address} is a special-purpose (non-public) address and must be blocked");
    }

    [Theory]
    [MemberData(nameof(PublicAddresses))]
    public void IsBlocked_PublicAddress_Passes(string address)
    {
        WebhookAddressGuard.IsBlocked(IPAddress.Parse(address)).ShouldBeFalse(
            $"{address} is a public address and must be allowed");
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.255")]
    [InlineData("::1")]
    public void AllowLoopback_RelaxesOnlyLoopback(string address)
    {
        // Blocked by default...
        WebhookAddressGuard.IsBlocked(IPAddress.Parse(address)).ShouldBeTrue();
        // ...but permitted when the loopback flag is set (the test-only escape hatch).
        WebhookAddressGuard.IsBlocked(IPAddress.Parse(address), allowLoopback: true).ShouldBeFalse();
    }

    [Theory]
    [InlineData("10.0.0.1")]           // private, not loopback
    [InlineData("169.254.169.254")]    // metadata, not loopback
    [InlineData("fc00::1")]            // unique-local, not loopback
    public void AllowLoopback_DoesNotRelaxOtherRanges(string address)
    {
        // The loopback allowance never unblocks a private / metadata / link-local target.
        WebhookAddressGuard.IsBlocked(IPAddress.Parse(address), allowLoopback: true).ShouldBeTrue();
    }
}
