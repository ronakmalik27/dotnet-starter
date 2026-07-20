using Microsoft.AspNetCore.Http;

namespace Starter.Api.Identity;

/// <summary>
/// The refresh-token transport for web: httpOnly, Secure,
/// SameSite=Strict, path-scoped to the refresh endpoint so no other
/// request ever carries it. The required X-Starter-Refresh companion header
/// is the CSRF belt over the SameSite suspenders - cross-site forms cannot
/// set custom headers.
/// </summary>
public static class RefreshCookie
{
    public const string Name = "starter_refresh";

    /// <summary>The one path the browser may send the cookie to.</summary>
    public const string Path = "/api/v1/auth/refresh";

    /// <summary>The required companion header and its only accepted value.</summary>
    public const string HeaderName = "X-Starter-Refresh";

    public const string HeaderValue = "1";

    internal static void Append(HttpResponse response, string refreshToken, DateTimeOffset expiresAt) =>
        response.Cookies.Append(Name, refreshToken, Options(expiresAt));

    internal static void Delete(HttpResponse response) =>
        // Same attributes as Append: browsers match cookies for deletion
        // by name + path.
        response.Cookies.Delete(Name, Options(expiresAt: null));

    private static CookieOptions Options(DateTimeOffset? expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = Path,
        Expires = expiresAt,
    };
}
