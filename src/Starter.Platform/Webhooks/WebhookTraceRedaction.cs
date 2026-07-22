using System.Diagnostics;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Keeps a tenant's receiver URL out of OpenTelemetry traces (webhooks.md section 5). A
/// receiver URL can embed a secret (Slack / Discord / Teams incoming-webhook URLs carry
/// the token in the path), which this feature cannot prevent at registration, and
/// HttpClient instrumentation records the request URL by default. The delivery client
/// stamps every outgoing request with <see cref="Marker"/> (via
/// <see cref="WebhookTraceMarkerHandler"/>); the composition root wires
/// <see cref="Enrich"/> as the HttpClient instrumentation's request enrichment, so a
/// marked request has its URL tags redacted on its own span before export - the app's HMAC
/// secret and the signature header are already safe (default instrumentation captures no
/// headers or bodies).
/// </summary>
public static class WebhookTraceRedaction
{
    /// <summary>The per-request marker the delivery client sets and the enrichment reads.</summary>
    public static readonly HttpRequestOptionsKey<bool> Marker = new("starter.webhooks.redact-url");

    private const string Redacted = "[redacted]";

    /// <summary>
    /// The HttpClient-instrumentation enrichment. For a request carrying
    /// <see cref="Marker"/>, overwrites the span's URL-bearing tags with a host-only,
    /// path/query-redacted form so a receiver-owned secret is not shipped to the OTLP
    /// backend. A non-webhook request is left untouched.
    /// </summary>
    public static void Enrich(Activity activity, HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(request);

        if (!request.Options.TryGetValue(Marker, out var redact) || !redact)
        {
            return;
        }

        var uri = request.RequestUri;
        var safe = uri is null ? Redacted : $"{uri.Scheme}://{uri.Authority}/{Redacted}";

        // Overwrite every URL-bearing tag name the HttpClient instrumentation may emit
        // (new semantic conventions and the legacy name), keeping the host (not a secret)
        // and dropping the secret-bearing path and query.
        activity.SetTag("url.full", safe);
        activity.SetTag("url.path", $"/{Redacted}");
        activity.SetTag("url.query", null);
        activity.SetTag("http.url", safe);
    }
}

/// <summary>
/// Stamps <see cref="WebhookTraceRedaction.Marker"/> on every outgoing delivery request
/// so the trace enrichment knows to redact its URL. Added to the delivery client's
/// pipeline; it changes no request behaviour.
/// </summary>
internal sealed class WebhookTraceMarkerHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Options.Set(WebhookTraceRedaction.Marker, true);
        return base.SendAsync(request, cancellationToken);
    }
}
