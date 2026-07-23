using System.Net;
using Microsoft.AspNetCore.Http;

namespace Starter.Platform.Auth.Conditions;

/// <summary>
/// The small, fixed request-attribute bag a conditional grant is evaluated
/// against (abac.md sections 3, 4): immutable, assembled once per request by the
/// gate. A condition reads exactly the attributes it needs and no more, so the
/// surface a policy can touch is bounded by design.
/// <para>
/// <see cref="Now"/> is stamped from the injected <c>Clock</c> (never
/// <c>DateTimeOffset.UtcNow</c> - the BannedApi arch test forbids it), so the time
/// source is testable. <see cref="ClientIp"/> is the socket's last hop
/// (<c>http.Connection.RemoteIpAddress</c>), trustworthy only behind a correctly
/// configured forwarded-headers setup (abac.md section 3); it is null when the
/// connection reports no address. <see cref="WorkspaceId"/> is the resolved
/// workspace when the request is workspace-scoped, else null.
/// <see cref="ResourceId"/> is a seam slot for a future resource-attribute
/// condition; no built-in reads it yet (abac.md section 9).
/// </para>
/// </summary>
public sealed record RequestAttributes
{
    /// <summary>The request instant in UTC, stamped from the injected Clock.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>The caller's client IP (http.Connection.RemoteIpAddress), or null when unknown.</summary>
    public required IPAddress? ClientIp { get; init; }

    /// <summary>The resolved workspace when workspace-scoped, else null.</summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>The route resource id; no built-in condition reads it yet (abac.md section 9).</summary>
    public Guid? ResourceId { get; init; }

    /// <summary>
    /// Assembles the bag from the current request: <paramref name="now"/> (the
    /// Clock-stamped instant) and the connection's last-hop client IP. The gate
    /// layers <see cref="WorkspaceId"/> on for a workspace-scoped check (a
    /// <c>with</c> expression), so this factory reads only what the request itself
    /// carries.
    /// </summary>
    public static RequestAttributes FromHttp(HttpContext http, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(http);

        return new RequestAttributes
        {
            Now = now,
            ClientIp = http.Connection.RemoteIpAddress,
        };
    }
}
