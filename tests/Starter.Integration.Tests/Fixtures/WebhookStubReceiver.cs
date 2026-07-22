using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// A minimal in-test HTTP receiver the delivery worker can POST to over loopback. It
/// records each request's body and signature header and answers with a configurable
/// status (settable mid-test, for the replay case). The worker reaches it because the
/// SSRF guard permits loopback in the test host (AllowLoopbackDelivery); the production
/// default still blocks loopback.
/// </summary>
internal sealed class WebhookStubReceiver : IAsyncDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentQueue<ReceivedWebhook> _received = new();
    private readonly Task _loop;

    public WebhookStubReceiver(int statusCode = 200)
    {
        StatusCode = statusCode;
        var port = FreePort();
        Url = $"http://127.0.0.1:{port}/hook";
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Start();
        _loop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>The endpoint URL to register (loopback http).</summary>
    public string Url { get; }

    /// <summary>The HTTP status the receiver answers with; settable mid-test.</summary>
    public int StatusCode { get; set; }

    /// <summary>Every request received, in arrival order.</summary>
    public IReadOnlyList<ReceivedWebhook> Received => _received.ToArray();

    public int Count => _received.Count;

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception)
            {
                // The listener was closed (dispose): stop accepting.
                return;
            }

            string body;
            using (var reader = new StreamReader(context.Request.InputStream))
            {
                body = await reader.ReadToEndAsync();
            }

            var signature = context.Request.Headers["X-Starter-Signature"];
            _received.Enqueue(new ReceivedWebhook(body, signature));

            context.Response.StatusCode = StatusCode;
            context.Response.Close();
        }
    }

    private static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Close();
        try
        {
            await _loop;
        }
        catch (Exception)
        {
            // The accept loop faults on close; nothing to do.
        }

        _cts.Dispose();
    }
}

/// <summary>A request the stub received: the raw body and the X-Starter-Signature header.</summary>
internal sealed record ReceivedWebhook(string Body, string? Signature);
