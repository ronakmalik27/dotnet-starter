using System.Text.Json;

namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// One condition KIND, stateless: the pluggable seam a real policy engine (Cedar,
/// Open Policy Agent) plugs into as ONE more registered evaluator, with no change
/// to the gate, the resolver, or the schema (abac.md section 4). The built-ins
/// (<see cref="IpCidrConditionEvaluator"/>, <see cref="TimeOfDayConditionEvaluator"/>)
/// prove the seam end to end.
/// </summary>
public interface IConditionEvaluator
{
    /// <summary>The discriminator this evaluator handles, e.g. "ip_cidr".</summary>
    string ConditionType { get; }

    /// <summary>
    /// Called at GRANT time: throws <see cref="ConditionFormatException"/> on a
    /// malformed payload (a typo'd CIDR, a bad time). Rejecting at write time turns
    /// a silent never-satisfied grant into a clear validation error.
    /// </summary>
    void Validate(JsonElement condition);

    /// <summary>
    /// Called at CHECK time. MUST fail closed: return false on any doubt (a missing
    /// attribute, a parse slip). Never throw for a data reason - <see cref="Validate"/>
    /// already ran at grant time.
    /// </summary>
    bool IsSatisfied(JsonElement condition, RequestAttributes attributes);
}
