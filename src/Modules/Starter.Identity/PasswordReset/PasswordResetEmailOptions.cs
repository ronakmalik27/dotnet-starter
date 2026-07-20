namespace Starter.Identity.PasswordReset;

/// <summary>
/// Password-reset email settings, bound from Auth:PasswordReset. The
/// UrlTemplate is the front-end reset page the recipient opens; its {token}
/// placeholder is replaced with the URL-encoded raw token when the email is
/// composed. The default points at a local SPA dev server; a real
/// deployment overrides it with its own web origin.
/// </summary>
internal sealed class PasswordResetEmailOptions
{
    public const string SectionName = "Auth:PasswordReset";

    /// <summary>
    /// The reset-password link template. The literal "{token}" is replaced
    /// with the URL-encoded reset token.
    /// </summary>
    public string UrlTemplate { get; set; } = "https://localhost:3000/reset-password?token={token}";
}
