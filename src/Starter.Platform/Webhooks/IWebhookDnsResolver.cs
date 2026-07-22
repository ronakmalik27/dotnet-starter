using System.Net;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Resolves a webhook target host to its IP addresses. Injected (not called statically)
/// so the SSRF connect callback resolves DNS exactly once through a seam the integration
/// suite can substitute - the test resolver maps known hostnames to chosen addresses so
/// the DNS-rebinding case (public at register, private at connect) is exercisable without
/// real DNS trickery. Production uses <see cref="SystemWebhookDnsResolver"/>.
/// </summary>
public interface IWebhookDnsResolver
{
    /// <summary>Resolves <paramref name="host"/> (a hostname or an IP literal) to its addresses.</summary>
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>
/// The production DNS resolver: <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>.
/// An IP literal resolves to itself with no lookup.
/// </summary>
public sealed class SystemWebhookDnsResolver : IWebhookDnsResolver
{
    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);

        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        return await Dns.GetHostAddressesAsync(host, cancellationToken);
    }
}
