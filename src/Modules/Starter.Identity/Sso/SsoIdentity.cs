namespace Starter.Identity.Sso;

/// <summary>
/// The claims a validated enterprise-SSO id_token proves: the stable OIDC subject
/// (the linking key WITHIN an issuer - matched together with the issuer, never
/// alone) and the email with its issuer-side verification state (only a VERIFIED
/// email participates in account linking). The generalized shape of
/// <c>GoogleIdentity</c>, carried per-tenant-issuer.
/// </summary>
internal sealed record SsoIdentity(string Subject, string Email, bool EmailVerified);
