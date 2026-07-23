using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Starter.Api.Auth;
using Starter.Tenancy;
using Starter.Platform.Tenancy;

namespace Starter.Api.Tenancy;

/// <summary>
/// HTTP composition for the SCIM 2.0 Users seam (sso-and-scim.md section 5): the
/// minimal path Okta / Azure AD outbound provisioning drives - POST (create-or-
/// ensure), GET by id, GET with the single <c>userName eq</c> filter, PUT
/// (replace/active), and DELETE (soft deactivate). Handlers are thin (HTTP &lt;-&gt;
/// SCIM DTO); the logic lives behind <see cref="ITenancyApi"/>, exactly like every
/// other feature.
/// <para>
/// The group is PINNED to the SCIM scheme (CRITICAL rule 2):
/// <c>RequireAuthorization(policy =&gt; policy.AddAuthenticationSchemes(Scim).RequireAuthenticatedUser())</c>
/// accepts ONLY a principal minted by the SCIM handler, even if the forwarding
/// selector were ever misconfigured. There is NO <c>RequirePermission</c> /
/// <c>RequireTenantRole</c> here by design: possession of the tid-scoped SCIM bearer
/// IS the authority for this surface, and the principal's synthetic sub resolves to
/// no user, so an accidental RBAC check would fail closed anyway. Errors use the SCIM
/// error envelope (<see cref="ScimProblems"/>), not the app's RFC 9457 shape.
/// </para>
/// <para>
/// Scope-creep guards (spec section 8): PATCH, /Groups, discovery, and bulk are NOT
/// mapped. The ONLY filter is a literal <c>userName eq "..."</c>; anything else is an
/// empty ListResponse. Any <c>roles</c> / <c>groups</c> / <c>entitlements</c> an IdP
/// sends is ignored by CONSTRUCTION - the request DTO does not bind them, so acting
/// on a smuggled privilege grant is impossible. A PUT cannot change the email (it
/// would re-key the global user); only <c>active</c> is honored.
/// </para>
/// </summary>
public static class ScimEndpoints
{
    private const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";

    private const string ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    public static IEndpointRouteBuilder MapScimEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Group-pinned to the Scim scheme (defense in depth) plus RequireTenant so an
        // unresolved tenant answers 400 before any work. The SCIM principal always
        // carries tid, so RequireTenant passes for a genuine SCIM request.
        var scim = app.MapGroup(ScimAuthenticationDefaults.PathPrefix)
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(ScimAuthenticationDefaults.ScimScheme)
                .RequireAuthenticatedUser())
            .RequireTenant();

        scim.MapPost("/Users", CreateAsync);
        scim.MapGet("/Users/{id}", GetAsync);
        scim.MapGet("/Users", ListAsync);
        scim.MapPut("/Users/{id}", ReplaceAsync);
        scim.MapDelete("/Users/{id}", DeleteAsync);

        return app;
    }

    private static async Task<IResult> CreateAsync(
        ScimUserRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // userName (the email) is the only required input; externalId round-trips.
        // active, roles, groups, and every other attribute are ignored on create.
        var result = await tenancy.ProvisionScimUserAsync(
            request.UserName ?? string.Empty, request.ExternalId, cancellationToken);
        return result.Match(
            provisioned =>
            {
                var resource = BuildUser(
                    http, provisioned.UserId, provisioned.Email, provisioned.Active, provisioned.ExternalId);
                // 201 for a fresh membership (with Location), 200 for an idempotent
                // ensure of an existing member.
                return provisioned.Created
                    ? Results.Json(resource, contentType: ScimContentType, statusCode: StatusCodes.Status201Created)
                    : Results.Json(resource, contentType: ScimContentType, statusCode: StatusCodes.Status200OK);
            },
            ScimProblems.From);
    }

    private static async Task<IResult> GetAsync(
        string id,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return ScimProblems.NotFound("No user with that id exists in this tenant.");
        }

        var user = await tenancy.GetScimUserAsync(userId, cancellationToken);
        return user is { } found
            ? Results.Json(
                BuildUser(http, found.UserId, found.Email, found.Active, found.ExternalId),
                contentType: ScimContentType)
            : ScimProblems.NotFound("No user with that id exists in this tenant.");
    }

    private static async Task<IResult> ListAsync(
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken,
        string? filter = null)
    {
        // The ONLY supported filter is the literal userName eq "..." reconciliation
        // clause. An absent or unsupported filter yields an empty ListResponse (never
        // a full enumeration, and never a general filter parser).
        var userName = ScimFilter.ParseUserNameEq(filter);
        if (userName is null)
        {
            return Results.Json(BuildList([]), contentType: ScimContentType);
        }

        var user = await tenancy.FindScimUserByUserNameAsync(userName, cancellationToken);
        var resources = user is { } found
            ? new[] { BuildUser(http, found.UserId, found.Email, found.Active, found.ExternalId) }
            : [];
        return Results.Json(BuildList(resources), contentType: ScimContentType);
    }

    private static async Task<IResult> ReplaceAsync(
        string id,
        ScimUserRequest request,
        ITenancyApi tenancy,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return ScimProblems.NotFound("No user with that id exists in this tenant.");
        }

        // Honor ONLY active (default true when absent). The email, roles, groups, and
        // every other attribute are echoed/ignored - a PUT never re-keys the user or
        // grants anything.
        var active = request.Active ?? true;
        var result = await tenancy.SetScimUserActiveAsync(userId, active, cancellationToken);
        return result.Match(
            user => Results.Json(
                BuildUser(http, user.UserId, user.Email, user.Active, user.ExternalId),
                contentType: ScimContentType),
            ScimProblems.From);
    }

    private static async Task<IResult> DeleteAsync(
        string id,
        ITenancyApi tenancy,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return ScimProblems.NotFound("No user with that id exists in this tenant.");
        }

        // DELETE is a SOFT deactivate (suspend), never a hard delete (audit). The
        // last-owner guard can refuse it (409); success is 204.
        var result = await tenancy.SetScimUserActiveAsync(userId, active: false, cancellationToken);
        return result.Match(
            _ => Results.NoContent(),
            ScimProblems.From);
    }

    private const string ScimContentType = "application/scim+json";

    private static ScimUserResource BuildUser(
        HttpContext http, Guid userId, string email, bool active, string? externalId) =>
        new(
            [UserSchema],
            userId.ToString(),
            externalId,
            email,
            active,
            [new ScimEmail(email, Primary: true)],
            new ScimMeta(
                "User",
                $"{http.Request.Scheme}://{http.Request.Host}{ScimAuthenticationDefaults.PathPrefix}/Users/{userId}"));

    private static ScimListResponse BuildList(ScimUserResource[] resources) =>
        new(
            [ListResponseSchema],
            resources.Length,
            1,
            resources.Length,
            resources);
}

/// <summary>
/// The SCIM User request body for POST / PUT. It binds ONLY the attributes this seam
/// acts on - <c>userName</c>, <c>externalId</c>, <c>active</c> - so any
/// <c>roles</c> / <c>groups</c> / <c>entitlements</c> an IdP sends is ignored by
/// construction (System.Text.Json drops unbound members), closing the
/// privilege-escalation-through-a-deferred-feature vector.
/// </summary>
public sealed record ScimUserRequest(
    [property: JsonPropertyName("userName")] string? UserName,
    [property: JsonPropertyName("externalId")] string? ExternalId,
    [property: JsonPropertyName("active")] bool? Active);

/// <summary>
/// The SCIM 2.0 core User resource (RFC 7643 section 4.1): <c>schemas</c>, <c>id</c>
/// (OUR global user guid, stable and resolvable by GET /Users/{id}), <c>externalId</c>
/// (the IdP's handle, omitted when absent), <c>userName</c> (the email), <c>active</c>
/// (membership status == Active), <c>emails</c>, and <c>meta</c>. Field names are
/// pinned so the shape is exact regardless of the host's JSON naming policy.
/// </summary>
public sealed record ScimUserResource(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("externalId")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? ExternalId,
    [property: JsonPropertyName("userName")] string UserName,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("emails")] IReadOnlyList<ScimEmail> Emails,
    [property: JsonPropertyName("meta")] ScimMeta Meta);

/// <summary>A SCIM multi-valued email entry: the address and whether it is the primary.</summary>
public sealed record ScimEmail(
    [property: JsonPropertyName("value")] string Value,
    [property: JsonPropertyName("primary")] bool Primary);

/// <summary>The SCIM resource <c>meta</c>: the resource type and its canonical location.</summary>
public sealed record ScimMeta(
    [property: JsonPropertyName("resourceType")] string ResourceType,
    [property: JsonPropertyName("location")] string Location);

/// <summary>
/// A SCIM 2.0 ListResponse (RFC 7644 section 3.4.2): <c>totalResults</c>,
/// <c>startIndex</c>, <c>itemsPerPage</c>, and the capital-R <c>Resources</c> array
/// (pinned so the SCIM-mandated casing survives the host's camelCase policy).
/// </summary>
public sealed record ScimListResponse(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("totalResults")] int TotalResults,
    [property: JsonPropertyName("startIndex")] int StartIndex,
    [property: JsonPropertyName("itemsPerPage")] int ItemsPerPage,
    [property: JsonPropertyName("Resources")] IReadOnlyList<ScimUserResource> Resources);

/// <summary>
/// The single SCIM filter this seam supports: the literal <c>userName eq "..."</c>
/// reconciliation clause every SCIM client issues (RFC 7644 section 3.4.2.2). Broader
/// filtering is a documented grow-into, so this is a fixed, dependency-free reader -
/// NOT a general filter parser: anything that is not exactly this clause returns null,
/// which the endpoint renders as an empty ListResponse.
/// </summary>
internal static class ScimFilter
{
    private const string Attribute = "userName";

    private const string Operator = "eq";

    public static string? ParseUserNameEq(string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return null;
        }

        var rest = filter.Trim();
        if (!rest.StartsWith(Attribute, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        rest = rest[Attribute.Length..].TrimStart();
        if (!rest.StartsWith(Operator, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        rest = rest[Operator.Length..].Trim();
        // The value must be a single double-quoted string literal.
        return rest.Length >= 2 && rest[0] == '"' && rest[^1] == '"'
            ? rest[1..^1]
            : null;
    }
}
