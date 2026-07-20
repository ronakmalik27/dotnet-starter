using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Starter.Platform.Auth;

/// <summary>
/// The operations a caller can request against an <see cref="IOwnedResource"/>,
/// as the framework's OperationAuthorizationRequirement so a resource check
/// reads AuthorizeAsync(user, resource, ResourceOperations.Read). The
/// instances are singletons: <see cref="ResourceOwnerAuthorizationHandler"/>
/// recognizes an operation by reference identity to one of these, so an
/// unrelated requirement (even one named "read") never matches.
/// </summary>
public static class ResourceOperations
{
    /// <summary>Read the resource.</summary>
    public static readonly OperationAuthorizationRequirement Read = new() { Name = "read" };

    /// <summary>Update the resource.</summary>
    public static readonly OperationAuthorizationRequirement Update = new() { Name = "update" };

    /// <summary>Delete the resource.</summary>
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = "delete" };
}
