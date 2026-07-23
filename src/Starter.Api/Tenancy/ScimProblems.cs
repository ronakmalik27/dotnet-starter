using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Starter.SharedKernel;

namespace Starter.Api.Tenancy;

/// <summary>
/// Shapes SCIM failures into the SCIM 2.0 error envelope
/// (<c>urn:ietf:params:scim:api:messages:2.0:Error</c>, RFC 7644 section 3.12),
/// NOT the app's RFC 9457 <c>starter:*</c> problem+json. This is a DELIBERATE
/// deviation, scoped ONLY to <c>/scim/v2</c>: a real Okta / Azure AD SCIM client
/// validates the SCIM envelope and would break on an RFC 9457 body. Do NOT "fix"
/// this back to <see cref="Starter.Platform.Http.StarterProblems"/> for consistency -
/// the SCIM surface is standards-bound, and its non-conformance would be a genuine
/// interop bug. The response carries the <c>application/scim+json</c> content type
/// and a body whose <c>status</c> is the HTTP status as a string.
/// </summary>
internal static class ScimProblems
{
    private const string ScimContentType = "application/scim+json";

    private const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";

    /// <summary>Maps a SharedKernel error to its SCIM error result, by kind.</summary>
    public static IResult From(Error error)
    {
        ArgumentNullException.ThrowIfNull(error);

        var (status, scimType) = error.Kind switch
        {
            // A bad SCIM value (a blank / non-email userName) is 400 invalidValue.
            ErrorKind.Validation => (StatusCodes.Status400BadRequest, "invalidValue"),
            ErrorKind.NotFound => (StatusCodes.Status404NotFound, (string?)null),
            // The last-owner refusal is a state conflict (never a 500 or a lockout).
            ErrorKind.Conflict => (StatusCodes.Status409Conflict, (string?)null),
            _ => (StatusCodes.Status400BadRequest, (string?)null),
        };
        return Build(status, error.Message, scimType);
    }

    /// <summary>A SCIM 404 with the given detail (a member absent from the token's tenant).</summary>
    public static IResult NotFound(string detail) =>
        Build(StatusCodes.Status404NotFound, detail, scimType: null);

    /// <summary>A SCIM 400 with the given detail and optional scimType (a malformed request).</summary>
    public static IResult BadRequest(string detail, string? scimType = "invalidValue") =>
        Build(StatusCodes.Status400BadRequest, detail, scimType);

    private static IResult Build(int status, string detail, string? scimType) =>
        Results.Json(
            new ScimError(
                [ErrorSchema], status.ToString(System.Globalization.CultureInfo.InvariantCulture), detail, scimType),
            contentType: ScimContentType,
            statusCode: status);
}

/// <summary>
/// The SCIM 2.0 Error resource body (RFC 7644 section 3.12): <c>schemas</c>, the HTTP
/// <c>status</c> as a string, a human <c>detail</c>, and an optional <c>scimType</c>.
/// Field names are pinned with <see cref="JsonPropertyNameAttribute"/> so the shape
/// is exact regardless of the host's JSON naming policy.
/// </summary>
internal sealed record ScimError(
    [property: JsonPropertyName("schemas")] IReadOnlyList<string> Schemas,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("scimType")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? ScimType);
