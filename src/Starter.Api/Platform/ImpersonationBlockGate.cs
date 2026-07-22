using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Platform;

/// <summary>
/// The destructive-op guard for impersonation (multi-tenancy.md section 7): an
/// endpoint filter that 403s any request acting under an impersonation token
/// (one carrying the imp claim) with the stable starter:impersonation-forbidden
/// problem. It is the conservative default a real app tightens per endpoint -
/// applied to the irreversible operations (note delete, member removal, ownership
/// transfer, tenant delete), never to reads and never to the platform-admin
/// endpoints themselves (a platform admin managing impersonation is not acting
/// under it). A single claim-presence check, no DB hit.
/// </summary>
public static class ImpersonationBlockGate
{
    /// <summary>Declares the endpoint refused under an impersonation token.</summary>
    public static TBuilder BlockUnderImpersonation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddEndpointFilterFactory((_, next) =>
            invocationContext => InvokeAsync(invocationContext, next));
    }

    private static async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        if (http.User.GetImpersonation() is not null)
        {
            return TypedResults.Problem(StarterProblems.ImpersonationForbidden(http));
        }

        return await next(context);
    }
}
