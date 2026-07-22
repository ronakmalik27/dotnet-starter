using System.Text;
using System.Text.Json;
using Starter.Platform.Events;

namespace Starter.Platform.Data;

/// <summary>
/// Renders the short, bounded, non-PII <c>summary</c> for an audit row from a
/// domain event (audit-log.md sections 3, 5). Platform cannot reference module
/// payload types (the dependency-shape arch test forbids it), so the summary is
/// composed by UNTYPED JSON traversal of the payload - the action plus its
/// well-known scalar fields, tolerating any of them being absent - never typed
/// deserialization. The payload is already "ids and scalars, never PII" (the
/// spine's rule), so echoing its scalars into the summary inherits that
/// discipline. Both the async tenant projection and the synchronous platform
/// writer render through here, so the rendering lives in one place.
/// </summary>
internal static class AuditSummary
{
    // A hard cap so a summary can never grow unbounded, whatever a future
    // payload carries. The action plus a handful of ids sits far under this.
    private const int MaxLength = 500;

    public static string Render(DomainEventRecord domainEvent)
    {
        var builder = new StringBuilder(domainEvent.EventType);

        try
        {
            using var document = JsonDocument.Parse(domainEvent.Payload);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    // Scalars only: skip nulls, objects, and arrays. Payloads are
                    // ids and scalars by rule, so this is the whole payload, but
                    // guarding keeps the summary a single flat sentence.
                    if (property.Value.ValueKind is JsonValueKind.String
                        or JsonValueKind.Number
                        or JsonValueKind.True
                        or JsonValueKind.False)
                    {
                        builder.Append(' ')
                            .Append(property.Name)
                            .Append('=')
                            .Append(property.Value.ToString());
                    }
                }
            }
        }
        catch (JsonException)
        {
            // A payload that is not a JSON object (should not happen for a
            // catalogue event) still yields the action alone - never a throw.
        }

        var summary = builder.ToString();
        return summary.Length <= MaxLength ? summary : summary[..MaxLength];
    }
}
