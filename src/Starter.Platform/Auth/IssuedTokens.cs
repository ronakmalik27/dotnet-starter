namespace Starter.Platform.Auth;

/// <summary>
/// The result of a successful login or refresh (FR-AUTH-04): a short-lived
/// ES256 access JWT plus one member of a rotating refresh-token family.
/// Lives in the platform rather than the Identity module because the module
/// surface exports no types beyond its Api interface and bootstrap class
/// (LLD section 1, ModuleSurfaceTests), and the platform already owns the
/// token contract constants the transport layers share.
/// </summary>
/// <param name="UserId">The authenticated user.</param>
/// <param name="SessionId">The sessions row backing the tokens (`sid`).</param>
/// <param name="AccessToken">The ES256 access JWT (doc 10 4.2).</param>
/// <param name="AccessTokenExpiresIn">Access token lifetime in seconds.</param>
/// <param name="RefreshToken">
/// The raw refresh token, held only long enough to leave in the transport
/// (httpOnly cookie on web, doc 10 4.3); the store keeps only its hash.
/// </param>
/// <param name="RefreshExpiresAt">
/// The family's absolute expiry; rotation never extends it (doc 10 4.2).
/// </param>
public sealed record IssuedTokens(
    Guid UserId,
    Guid SessionId,
    string AccessToken,
    int AccessTokenExpiresIn,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAt);
