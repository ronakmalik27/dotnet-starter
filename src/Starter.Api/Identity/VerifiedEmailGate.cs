using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Identity;
using Starter.Platform.Auth;
using Starter.Platform.Http;

namespace Starter.Api.Identity;

/// <summary>
/// The `vrf` capability gate: an endpoint filter that 403s any
/// authenticated caller whose email
/// is not verified, with the starter:verification-required problem so the
/// UI can render the reason inline. Composes AFTER
/// RequireAuthorization, exactly as [Authorize] gates `user`-cap
/// endpoints; fail-closed on a missing or unparseable sub claim (401) and
/// on a missing account row (403). The always-verified write actions -
/// creating a record, uploading a file, updating account settings - attach
/// this when their HTTP endpoints land; until then the gate ships as a
/// tested, reusable piece (a deferred-wiring pattern).
/// </summary>
public static class VerifiedEmailGate
{
    /// <summary>Declares the endpoint `vrf`: verified account required.</summary>
    public static TBuilder RequireVerifiedEmail<TBuilder>(this TBuilder builder)
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

        // RequireAuthorization already ran for a correctly-composed
        // endpoint; this guard makes the gate itself fail closed when it
        // is composed onto an anonymous route by mistake.
        var userId = http.User.GetUserId();
        if (userId is null)
        {
            return TypedResults.Problem(StarterProblems.Unauthorized(http));
        }

        var identity = http.RequestServices.GetRequiredService<IIdentityApi>();
        if (!await identity.IsEmailVerifiedAsync(userId.Value, http.RequestAborted))
        {
            return TypedResults.Problem(StarterProblems.VerificationRequired(http));
        }

        return await next(context);
    }
}
