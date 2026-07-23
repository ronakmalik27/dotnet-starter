namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// A condition payload is malformed: an unknown discriminator, missing or
/// wrong-typed fields, or a value the evaluator cannot parse (a bad CIDR, a
/// non-<c>HH:mm</c> time). Thrown only on the GRANT path
/// (<see cref="IConditionEvaluator.Validate"/> and
/// <see cref="ConditionEvaluatorRegistry.Validate"/>), so a bad condition is
/// rejected at write time rather than becoming a silent never-satisfied grant.
/// The CHECK path never throws it: it fails closed to a denied permission.
/// </summary>
public sealed class ConditionFormatException(string message) : Exception(message);
