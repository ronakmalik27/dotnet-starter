using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Starter.Platform.Auth;

/// <summary>
/// The third authorization layer (multi-tenancy.md section 5, layer 3):
/// within a tenant an admin or above may manage ANY resource, not only the ones
/// they own. It grants the same read/update/delete
/// <see cref="ResourceOperations"/> the owner handler grants, but for a caller
/// whose role in the active tenant is admin or higher. It runs ALONGSIDE
/// <see cref="ResourceOwnerAuthorizationHandler"/> (ASP.NET Core grants if ANY
/// handler succeeds), so the effective rule is "owner OR tenant-admin+", and a
/// plain member still only manages resources they own.
/// <para>
/// It never calls <c>context.Fail()</c> - absence of success is failure, so a
/// veto here would override the owner handler. The role lookup comes through the
/// platform-declared <see cref="ITenantRoleReader"/> seam (Tenancy implements it,
/// the composition root bridges it), so the platform never references a module.
/// The boundary is already enforced below this: a cross-tenant resource is
/// invisible to the endpoint's RLS-bound read (a 404 before authorization), so
/// this only ever grants over resources in the caller's own active tenant.
/// </para>
/// </summary>
public sealed class TenantAdminResourceAuthorizationHandler(ITenantRoleReader roleReader)
    : AuthorizationHandler<OperationAuthorizationRequirement, IOwnedResource>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        IOwnedResource resource)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);
        ArgumentNullException.ThrowIfNull(resource);

        // Only the operations the resource model owns, matched by reference
        // identity to the ResourceOperations singletons - exactly as the owner
        // handler does, so a foreign requirement that merely shares a name is
        // never one of ours.
        if (!IsKnownOperation(requirement))
        {
            return;
        }

        var callerId = context.User.GetUserId();
        if (callerId is null)
        {
            return;
        }

        // The owner handler already grants the owner; skip the membership read
        // on that common path so ownership authorization costs no extra query
        // when the caller owns the resource.
        if (callerId.Value == resource.OwnerUserId)
        {
            return;
        }

        // The authorization pipeline carries no cancellation token; the lookup
        // is a single indexed RLS-bound read, so None is acceptable here.
        var role = await roleReader.GetCallerRoleAsync(callerId.Value, CancellationToken.None);
        if (role is { } tenantRole && tenantRole >= TenantRole.Admin)
        {
            context.Succeed(requirement);
        }
    }

    private static bool IsKnownOperation(OperationAuthorizationRequirement requirement) =>
        ReferenceEquals(requirement, ResourceOperations.Read)
        || ReferenceEquals(requirement, ResourceOperations.Update)
        || ReferenceEquals(requirement, ResourceOperations.Delete);
}
