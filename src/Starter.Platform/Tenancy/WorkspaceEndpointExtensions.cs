using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Http;

namespace Starter.Platform.Tenancy;

/// <summary>
/// Endpoint opt-in for the WORKSPACE requirement (multi-tenancy.md section 12).
/// A workspace-scoped route reads <c>{workspaceId}</c> from its own path,
/// confirms the workspace exists under the active tenant's RLS through
/// <see cref="IWorkspaceReader"/>, and binds it into the request-scoped
/// <see cref="IWorkspaceContext"/> so handlers can stamp and filter on it. A
/// workspaceId belonging to another tenant is invisible under RLS, so it reads as
/// not-found and answers 404 <c>starter:workspace-not-found</c> - never 403,
/// which is reserved for a caller who lacks a permission in a workspace that DOES
/// exist. The 404-before-403 ordering falls out of composition: this gate is
/// applied at the workspace route GROUP (outermost), so it runs before the
/// per-route workspace-permission gate.
/// </summary>
public static class WorkspaceEndpointExtensions
{
    /// <summary>The route value a workspace-scoped path carries the workspace id in.</summary>
    public const string RouteKey = "workspaceId";

    /// <summary>
    /// Marks an endpoint (or group) workspace-scoped: it resolves and validates
    /// the <c>{workspaceId}</c> route segment. Compose it AFTER
    /// <c>RequireTenant()</c> (a workspace read is RLS-bound to the active tenant,
    /// so the tenant must resolve first) and BEFORE any workspace-permission gate
    /// (so a bad workspace is 404, not 403). Fail-closed: a missing, unparseable,
    /// or cross-tenant workspace is 404.
    /// </summary>
    public static TBuilder RequireWorkspace<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddEndpointFilter(static async (context, next) =>
        {
            var http = context.HttpContext;
            if (!TryReadWorkspaceId(http, out var workspaceId))
            {
                return TypedResults.Problem(StarterProblems.WorkspaceNotFound(http));
            }

            // The lookup is RLS-bound to the active tenant: a workspace from
            // another tenant is invisible and reads as not-existing, so a
            // cross-tenant id gets the same 404 as an unknown one (never 403,
            // never a confirmation that it exists elsewhere). One read carries the
            // archived state too, so RequireActiveWorkspace needs no round-trip.
            var reader = http.RequestServices.GetRequiredService<IWorkspaceReader>();
            var lookup = await reader.LookupWorkspaceAsync(workspaceId, http.RequestAborted);
            if (!lookup.Exists)
            {
                return TypedResults.Problem(StarterProblems.WorkspaceNotFound(http));
            }

            // Bind the validated workspace (and its lifecycle state) so downstream
            // handlers, the workspace-permission gate, and RequireActiveWorkspace
            // act within it.
            var workspaceContext = (WorkspaceContext)http.RequestServices.GetRequiredService<IWorkspaceContext>();
            workspaceContext.Resolve(workspaceId, lookup.Archived);

            return await next(context);
        });
    }

    /// <summary>
    /// Marks a MUTATING workspace-scoped route as requiring an ACTIVE workspace
    /// (multi-tenancy.md section 20): an archived workspace is read-only, so a
    /// write is refused with 409 <c>starter:workspace-archived</c>. Compose it
    /// AFTER <c>RequireWorkspace</c> (which binds the workspace and its state) and,
    /// where the route is permission-gated, after the permission gate (authorize
    /// first, then refuse on state). Apply it only to writes: reads of an archived
    /// workspace stay fully served, and the workspace-management operations
    /// themselves (rename, archive, unarchive) act on the workspace entity at
    /// tenant scope and must keep working while archived, so they do NOT carry it.
    /// </summary>
    public static TBuilder RequireActiveWorkspace<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddEndpointFilter(static async (context, next) =>
        {
            var http = context.HttpContext;
            var workspace = http.RequestServices.GetRequiredService<IWorkspaceContext>();

            // RequireWorkspace runs first (group level) and binds the workspace.
            // If it is somehow unresolved the route was mis-composed; fail closed
            // with 404 rather than allowing a write against no workspace.
            if (!workspace.IsResolved)
            {
                return TypedResults.Problem(StarterProblems.WorkspaceNotFound(http));
            }

            if (workspace.IsArchived)
            {
                return TypedResults.Problem(StarterProblems.WorkspaceArchived(http));
            }

            return await next(context);
        });
    }

    /// <summary>
    /// Reads the <c>{workspaceId}</c> route value as a non-empty Guid. The route
    /// constraint (<c>:guid</c>) already rejects a non-Guid at routing time; this
    /// is the fail-closed backstop if the gate is composed onto a route with no
    /// such segment.
    /// </summary>
    private static bool TryReadWorkspaceId(HttpContext http, out Guid workspaceId)
    {
        workspaceId = Guid.Empty;
        return http.Request.RouteValues.TryGetValue(RouteKey, out var raw)
            && raw is not null
            && Guid.TryParse(raw.ToString(), out workspaceId)
            && workspaceId != Guid.Empty;
    }
}
