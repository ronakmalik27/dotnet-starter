namespace Starter.Identity.Verification;

/// <summary>
/// Verification-email settings, bound from Auth:Verification. The
/// UrlTemplate is the front-end verify page the recipient opens; its
/// {token} placeholder is replaced with the URL-encoded raw token when the
/// email is composed. The default points at a local SPA dev server; a real
/// deployment overrides it with its own web origin.
/// </summary>
internal sealed class VerificationEmailOptions
{
    public const string SectionName = "Auth:Verification";

    /// <summary>
    /// The verify-email link template. The literal "{token}" is replaced
    /// with the URL-encoded verification token.
    /// </summary>
    public string UrlTemplate { get; set; } = "https://localhost:3000/verify-email?token={token}";
}
