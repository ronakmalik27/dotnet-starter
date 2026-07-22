namespace Starter.Tenancy.ServiceAccounts;

/// <summary>
/// Service-account / API-key options (config section <c>Tenancy:ApiKeys</c>).
/// The last_used_at write is throttled (service-accounts.md section 6): a key
/// hammered by a busy client advances last_used_at at most once per this window,
/// keeping the auth path lookup-light. The default (5 minutes) is the sane
/// starter value; last_used_at is approximate by design (accurate to the
/// throttle), which is the right trade for a "when was this key last active"
/// signal - the exact per-call record is the audit log, not this column.
/// </summary>
internal sealed class ApiKeyOptions
{
    public const string SectionName = "Tenancy:ApiKeys";

    /// <summary>The last_used_at coalescing window. A key writes at most once per window, not per request.</summary>
    public TimeSpan LastUsedThrottle { get; init; } = TimeSpan.FromMinutes(5);
}
