namespace Starter.Platform.Auth;

/// <summary>
/// The result of a successful login or refresh: a short-lived
/// ES256 access JWT plus one member of a rotating refresh-token family.
/// Lives in the platform rather than the Identity module because the module
/// surface exports no types beyond its Api interface and bootstrap class
/// (ModuleSurfaceTests), and the platform already owns the
/// token contract constants the transport layers share.
/// </summary>
/// <param name="UserId">The authenticated user.</param>
/// <param name="SessionId">The sessions row backing the tokens (`sid`).</param>
/// <param name="AccessToken">The ES256 access JWT.</param>
/// <param name="AccessTokenExpiresIn">Access token lifetime in seconds.</param>
/// <param name="RefreshToken">
/// The raw refresh token, held only long enough to leave in the transport
/// (httpOnly cookie on web); the store keeps only its hash.
/// </param>
/// <param name="RefreshExpiresAt">
/// The family's absolute expiry; rotation never extends it.
/// </param>
public sealed record IssuedTokens(
    Guid UserId,
    Guid SessionId,
    string AccessToken,
    int AccessTokenExpiresIn,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAt);
