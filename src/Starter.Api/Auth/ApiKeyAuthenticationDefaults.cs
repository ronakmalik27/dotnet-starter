namespace Starter.Api.Auth;

/// <summary>
/// The scheme names for the additive API-key authentication
/// (service-accounts.md section 3). The <c>ApiKey</c> scheme validates a
/// service-account key; the <c>Starter</c> policy (forwarding) scheme is the
/// default authenticate scheme, routing each request to <c>ApiKey</c> or the JWT
/// <c>Bearer</c> scheme by the credential it presents. The JWT path is unchanged.
/// </summary>
public static class ApiKeyAuthenticationDefaults
{
    /// <summary>The API-key authentication scheme (the <see cref="ApiKeyAuthenticationHandler"/>).</summary>
    public const string ApiKeyScheme = "ApiKey";

    /// <summary>The forwarding policy scheme that selects ApiKey or Bearer per request.</summary>
    public const string PolicyScheme = "Starter";
}
