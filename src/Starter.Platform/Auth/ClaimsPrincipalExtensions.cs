using System.Security.Claims;

namespace Starter.Platform.Auth;

/// <summary>
/// The one place the caller's user id is read off a principal: the sub claim
/// (<see cref="StarterClaims.Sub"/>) parsed as a Guid. Every endpoint and
/// gate that needs the authenticated user id goes through here rather than
/// re-parsing the claim inline, so the token contract has a single reader.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// The caller's user id from the sub claim, or null when the claim is
    /// absent or unparseable (an anonymous caller, or a token without a sub).
    /// Callers fail closed on null.
    /// </summary>
    public static Guid? GetUserId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var sub = principal.FindFirst(StarterClaims.Sub)?.Value;
        return Guid.TryParse(sub, out var userId) ? userId : null;
    }

    /// <summary>
    /// The session id backing this token from the sid claim
    /// (<see cref="StarterClaims.Sid"/>), or null when the claim is absent or
    /// unparseable. The tenant-switch mint reads it to reissue the access token
    /// for the same session. Callers fail closed on null.
    /// </summary>
    public static Guid? GetSessionId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var sid = principal.FindFirst(StarterClaims.Sid)?.Value;
        return Guid.TryParse(sid, out var sessionId) ? sessionId : null;
    }
}
