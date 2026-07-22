using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Builds the delivered body (webhooks.md section 5): a stable envelope
/// <c>{ id, type, occurredAt, data }</c> where <c>id</c> is the delivery id (so the
/// receiver can dedupe under at-least-once delivery), <c>type</c> is the event type,
/// <c>occurredAt</c> is the event instant, and <c>data</c> is the event payload verbatim
/// (raw JSON, not a re-escaped string). The payload comes from a serialized domain event,
/// so it is always valid JSON; a payload that somehow is not degrades to a JSON null
/// rather than throwing.
/// </summary>
internal static class WebhookEnvelope
{
    public static string Build(Guid deliveryId, string eventType, DateTimeOffset occurredAt, string payloadJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);
        ArgumentNullException.ThrowIfNull(payloadJson);

        var envelope = new JsonObject
        {
            ["id"] = deliveryId.ToString(),
            ["type"] = eventType,
            ["occurredAt"] = occurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            ["data"] = ParseData(payloadJson),
        };

        return envelope.ToJsonString();
    }

    private static JsonNode? ParseData(string payloadJson)
    {
        try
        {
            return JsonNode.Parse(payloadJson);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
