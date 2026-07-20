namespace Starter.Platform.Auth;

/// <summary>
/// The marker for a per-entity-owned resource: a resource whose access is
/// decided against the id of the user who owns it, not against a role or
/// scope in the token. This is the whole shape of the starter's
/// authorization model - the access JWT carries no roles by design
/// (see <see cref="StarterClaims"/>); permission is resolved per request
/// against the entity.
/// </summary>
public interface IOwnedResource
{
    /// <summary>The id of the user who owns this resource.</summary>
    Guid OwnerUserId { get; }
}

/// <summary>
/// A lightweight owner wrapper so a composition or endpoint layer can
/// authorize against an owner id without exposing a module's internal
/// entity: the endpoint reads the owner id off a module's primitive-only
/// read result and authorizes against this, never against the row itself.
/// </summary>
public sealed record OwnedResource(Guid OwnerUserId) : IOwnedResource;
