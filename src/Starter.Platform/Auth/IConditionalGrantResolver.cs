using Starter.Platform.Auth.Conditions;

namespace Starter.Platform.Auth;

/// <summary>
/// The narrow seam the platform's permission gate uses to consult a caller's
/// CONDITIONAL grants (abac.md section 5), a sibling port to
/// <see cref="IPermissionResolver"/> - declared in the platform so the platform
/// never references the Tenancy module. The Tenancy module implements it as a
/// request-path RLS read (the caller's <c>condition IS NOT NULL</c> grants,
/// visible only under the active tenant's GUC), evaluating each matching grant's
/// condition live against the passed <see cref="RequestAttributes"/>; the
/// composition root bridges this port to that implementation, so there is one
/// resolver and no drift.
/// <para>
/// It is the Tier-2 fallthrough: the gate calls it only on a Tier-1
/// (unconditional) miss, so an RBAC-authorized caller pays nothing. It is
/// deliberately NOT folded into the already-large <c>ITenancyApi</c> facade: it is
/// single-purpose and the gate resolves it directly.
/// </para>
/// </summary>
public interface IConditionalGrantResolver
{
    /// <summary>
    /// True iff the caller holds a CONDITIONAL grant conferring
    /// <paramref name="permission"/> at the scope whose condition is satisfied by
    /// <paramref name="attributes"/>. Fail-closed: no such grant, all conditions
    /// false, or any evaluation error resolves to false. A null
    /// <paramref name="workspaceId"/> is tenant scope; a value adds that
    /// workspace's conditional grants (downward inheritance). Applies the SAME
    /// active-membership gate as <see cref="IPermissionResolver"/>, so a suspended
    /// member reaches no conditional grant either.
    /// </summary>
    Task<bool> IsGrantedAsync(
        Guid principalId,
        string principalType,
        string permission,
        RequestAttributes attributes,
        Guid? workspaceId,
        CancellationToken cancellationToken);
}
