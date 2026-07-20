using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Starter.Platform.Auth;

/// <summary>
/// The one resource-based rule the starter ships: a caller may read, update,
/// or delete an <see cref="IOwnedResource"/> only when they own it. Succeeds
/// for a known <see cref="ResourceOperations"/> operation whose resource's
/// owner is the caller's sub; stays silent otherwise. It never calls
/// <c>context.Fail()</c> - the standard ASP.NET Core pattern is that absence
/// of success is failure, so a Fail() here would veto any other handler that
/// might legitimately grant access on a different requirement.
/// </summary>
public sealed class ResourceOwnerAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, IOwnedResource>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        IOwnedResource resource)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);
        ArgumentNullException.ThrowIfNull(resource);

        // Only the operations this handler owns, matched by reference to the
        // ResourceOperations singletons. A caller-supplied requirement that
        // merely shares a Name is not one of ours and is left unhandled.
        if (!IsKnownOperation(requirement))
        {
            return Task.CompletedTask;
        }

        var callerId = context.User.GetUserId();
        if (callerId is not null && callerId.Value == resource.OwnerUserId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    private static bool IsKnownOperation(OperationAuthorizationRequirement requirement) =>
        ReferenceEquals(requirement, ResourceOperations.Read)
        || ReferenceEquals(requirement, ResourceOperations.Update)
        || ReferenceEquals(requirement, ResourceOperations.Delete);
}
