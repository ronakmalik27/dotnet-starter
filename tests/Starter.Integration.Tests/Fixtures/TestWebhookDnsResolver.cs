using System.Collections.Concurrent;
using System.Net;
using Starter.Platform.Webhooks;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// A test <see cref="IWebhookDnsResolver"/> that maps chosen hostnames to chosen
/// addresses, so the SSRF connect callback and the register-time check resolve through a
/// seam the test controls. A mapping can be changed mid-test (the DNS-rebinding case:
/// public at register, private at connect). Unknown hosts fall back to the real resolver,
/// so IP literals and a test-local loopback receiver still work. The integration
/// collection runs sequentially and each test uses a unique hostname, so the shared map
/// does not bleed between tests.
/// </summary>
internal sealed class TestWebhookDnsResolver : IWebhookDnsResolver
{
    private readonly ConcurrentDictionary<string, IPAddress[]> _map = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Maps (or re-maps) a host to one or more IP literals.</summary>
    public void Map(string host, params string[] addresses) =>
        _map[host] = addresses.Select(IPAddress.Parse).ToArray();

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        if (_map.TryGetValue(host, out var mapped))
        {
            return mapped;
        }

        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        return await Dns.GetHostAddressesAsync(host, cancellationToken);
    }
}
