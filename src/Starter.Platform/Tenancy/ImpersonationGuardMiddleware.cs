using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Platform.Tenancy;

/// <summary>
/// The per-request impersonation guard (multi-tenancy.md section 7): for a
/// request whose token carries the imp / impgrant claims it re-checks the
/// backing grant on the bypass path, and rejects with 401
/// <c>starter:impersonation-ended</c> when the grant does not exist, was ended
/// early, or has passed its expiry. So ending a session takes effect on the
/// very next request, not only when the short token expires. For a request with
/// NO imp claim - the overwhelming majority - it does a single claim-presence
/// check and nothing else (no DB hit, no service resolution).
/// <para>
/// It runs right AFTER authentication (so the principal is populated) and BEFORE
/// authorization and tenant resolution, so a revoked session is stopped before
/// any endpoint, gate, or tenant-scoped work runs.
/// </para>
/// </summary>
public sealed class ImpersonationGuardMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var impersonation = context.User.GetImpersonation();
        if (impersonation is null)
        {
            // The common path: a normal token, no impersonation. Do nothing.
            await next(context);
            return;
        }

        var reader = context.RequestServices.GetRequiredService<IImpersonationGrantReader>();
        if (!await reader.IsGrantActiveAsync(impersonation.GrantId, context.RequestAborted))
        {
            await WriteEndedAsync(context);
            return;
        }

        await next(context);
    }

    private static async Task WriteEndedAsync(HttpContext context)
    {
        var problem = StarterProblems.ImpersonationEnded(context);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/problem+json";
        await context.Response.WriteAsJsonAsync(
            problem, problem.GetType(), options: null, contentType: "application/problem+json", context.RequestAborted);
    }
}

/// <summary>Pipeline registration for <see cref="ImpersonationGuardMiddleware"/>.</summary>
public static class ImpersonationGuardApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the per-request impersonation guard. Register it immediately after
    /// UseAuthentication (the principal must be populated) and before
    /// UseAuthorization and tenant resolution, so a request on an ended grant is
    /// rejected before any endpoint runs.
    /// </summary>
    public static IApplicationBuilder UseStarterImpersonationGuard(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<ImpersonationGuardMiddleware>();
    }
}
