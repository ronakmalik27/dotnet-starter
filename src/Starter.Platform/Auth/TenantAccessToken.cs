namespace Starter.Platform.Auth;

/// <summary>
/// A tenant-switch mint: a fresh ES256 access JWT carrying the <c>tid</c> claim
/// for the selected tenant, with no new refresh token (the refresh family is
/// unchanged - only the short-lived access token is reissued). Lives in the
/// platform alongside <see cref="IssuedTokens"/> for the same reason: a module
/// exports no types beyond its Api interface and bootstrap class, and the
/// transport layer composes over this contract.
/// </summary>
/// <param name="AccessToken">The ES256 access JWT carrying <c>tid</c>.</param>
/// <param name="AccessTokenExpiresIn">Access token lifetime in seconds.</param>
public sealed record TenantAccessToken(string AccessToken, int AccessTokenExpiresIn);
