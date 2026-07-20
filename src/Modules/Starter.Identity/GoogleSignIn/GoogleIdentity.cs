namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// The claims a validated Google ID token proves: the stable OIDC subject
/// (the linking key - Google documents that email can change, sub cannot)
/// and the email with its issuer-side verification state (SRS 5.3: only a
/// VERIFIED email participates in account linking).
/// </summary>
internal sealed record GoogleIdentity(string Subject, string Email, bool EmailVerified);
