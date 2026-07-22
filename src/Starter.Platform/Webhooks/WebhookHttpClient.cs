using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Starter.Platform.Webhooks;

/// <summary>
/// The SSRF-guarded delivery HTTP client (webhooks.md section 6). A named client whose
/// primary <see cref="SocketsHttpHandler"/> carries a <see cref="SocketsHttpHandler.ConnectCallback"/>
/// that resolves DNS exactly ONCE, validates every returned address against the IANA
/// blocklist, then opens the socket directly to a validated <see cref="IPAddress"/> -
/// never handing the hostname to a second resolver, which is the TOCTOU that DNS
/// rebinding exploits. Redirects are off (a 3xx is a failed delivery), so a redirect
/// cannot bounce to a blocked host after the check.
/// </summary>
internal static class WebhookHttpClient
{
    /// <summary>The named HttpClient the delivery worker resolves per attempt.</summary>
    public const string ClientName = "webhooks";

    /// <summary>
    /// Builds the SSRF-guarded primary handler. The DNS resolver and the loopback policy
    /// are captured from DI at build time; the resolver instance is stable, so the
    /// callback sees current mappings on every connect (the seam the rebinding test uses).
    /// </summary>
    public static SocketsHttpHandler CreatePrimaryHandler(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var resolver = services.GetRequiredService<IWebhookDnsResolver>();
        var allowLoopback = services.GetRequiredService<IOptions<WebhookOptions>>().Value.AllowLoopbackDelivery;

        return new SocketsHttpHandler
        {
            // A 3xx is a failed delivery: never follow it, so a redirect cannot bounce
            // to a blocked host after the connect-time check has passed.
            AllowAutoRedirect = false,
            ConnectCallback = (context, cancellationToken) =>
                ConnectAsync(context, resolver, allowLoopback, cancellationToken),
        };
    }

    private static async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        IWebhookDnsResolver resolver,
        bool allowLoopback,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;

        // Resolve exactly ONCE.
        var addresses = await resolver.ResolveAsync(host, cancellationToken);
        if (addresses.Count == 0)
        {
            throw new WebhookConnectException("The delivery host resolved to no addresses.");
        }

        // Validate EVERY returned address; reject the whole connect if any is blocked
        // (a rebinding answer of [public, private] never squeaks through on the public one).
        foreach (var address in addresses)
        {
            if (WebhookAddressGuard.IsBlocked(address, allowLoopback))
            {
                throw new WebhookConnectException("The delivery target resolves to a blocked (non-public) address.");
            }
        }

        // Connect directly to a VALIDATED ip - never hand the hostname back to a second
        // resolver (that second resolution is the rebinding TOCTOU).
        var target = addresses[0];
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

/// <summary>
/// A connect-time SSRF refusal: the delivery target resolved to a blocked address, or to
/// none. Surfaces to the worker as a transport failure (a bounded, non-PII last-error),
/// so the delivery backs off and dead-letters like any other unreachable endpoint.
/// </summary>
public sealed class WebhookConnectException : Exception
{
    public WebhookConnectException(string message)
        : base(message)
    {
    }
}
