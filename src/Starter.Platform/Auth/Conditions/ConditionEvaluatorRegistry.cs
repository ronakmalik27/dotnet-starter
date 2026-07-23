using System.Collections.Frozen;
using System.Text.Json;

namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// The condition-evaluator registry (abac.md section 4): a frozen
/// <c>type -&gt; IConditionEvaluator</c> map built once from the registered
/// evaluators. THIS registry is the Cedar / OPA integration point - a real policy
/// engine ships as ONE more <see cref="IConditionEvaluator"/> registered here, and
/// nothing else in the gate, the resolver, or the schema changes.
/// <para>
/// It is the single place an "unknown type" is decided, and it decides DENY: the
/// CHECK path (<see cref="IsSatisfied"/>) is fail-closed - an unknown type, a parse
/// failure, or an evaluator that throws all return false, so an unrecognized or
/// unparseable condition can never widen access. The GRANT path
/// (<see cref="Validate"/>) is strict - it throws
/// <see cref="ConditionFormatException"/> so a bad condition is rejected at write
/// time. A singleton (stateless once frozen).
/// </para>
/// </summary>
public sealed class ConditionEvaluatorRegistry
{
    private const string TypeProperty = "type";

    private readonly FrozenDictionary<string, IConditionEvaluator> _evaluators;

    public ConditionEvaluatorRegistry(IEnumerable<IConditionEvaluator> evaluators)
    {
        ArgumentNullException.ThrowIfNull(evaluators);

        _evaluators = evaluators.ToFrozenDictionary(
            evaluator => evaluator.ConditionType, StringComparer.Ordinal);
    }

    /// <summary>
    /// GRANT path: parses the envelope, requires a non-empty known <c>type</c>, and
    /// delegates to that evaluator's <see cref="IConditionEvaluator.Validate"/>.
    /// Throws <see cref="ConditionFormatException"/> on malformed JSON, an unknown
    /// type, or a bad payload. Returns the validated condition <c>type</c> (the
    /// discriminator), so the grant path can record it on the audit event without a
    /// second parse.
    /// </summary>
    public string Validate(string conditionJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(conditionJson);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(conditionJson);
        }
        catch (JsonException exception)
        {
            throw new ConditionFormatException($"The condition is not well-formed JSON: {exception.Message}");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(TypeProperty, out var typeElement)
                || typeElement.ValueKind != JsonValueKind.String
                || typeElement.GetString() is not { Length: > 0 } type)
            {
                throw new ConditionFormatException("A condition requires a non-empty string 'type' discriminator.");
            }

            if (!_evaluators.TryGetValue(type, out var evaluator))
            {
                throw new ConditionFormatException($"Unknown condition type '{type}'.");
            }

            evaluator.Validate(root);
            return type;
        }
    }

    /// <summary>
    /// CHECK path: parses the envelope, looks up the evaluator by <c>type</c>, and
    /// delegates to its <see cref="IConditionEvaluator.IsSatisfied"/>. Fail-closed
    /// everywhere - malformed JSON, a missing or unknown type, or an evaluator that
    /// throws all return false, so a condition that cannot be evaluated never
    /// confers the permission.
    /// </summary>
    public bool IsSatisfied(string conditionJson, RequestAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);

        if (string.IsNullOrWhiteSpace(conditionJson))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(conditionJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(TypeProperty, out var typeElement)
                || typeElement.ValueKind != JsonValueKind.String
                || typeElement.GetString() is not { Length: > 0 } type
                || !_evaluators.TryGetValue(type, out var evaluator))
            {
                return false;
            }

            return evaluator.IsSatisfied(root, attributes);
        }
        catch (JsonException)
        {
            // A malformed condition at check time should not happen (Validate ran at
            // grant time), but a parse slip fails closed all the same.
            return false;
        }
        catch (Exception)
        {
            // An evaluator that throws for any reason denies: a security condition
            // that cannot be evaluated must never widen access (abac.md section 7).
            return false;
        }
    }
}
