namespace Starter.Identity.Mfa;

/// <summary>
/// Builds the <c>otpauth://totp/...</c> provisioning URI an authenticator app
/// consumes (mfa-totp.md section 4). The issuer and the email label segment
/// are percent-encoded with <see cref="Uri.EscapeDataString"/>, so an email or
/// issuer carrying reserved URI characters cannot produce a malformed URI. The
/// base32 secret is already URI-safe (A-Z2-7).
/// </summary>
internal static class OtpAuthUri
{
    /// <summary>The generic issuer label shown in the authenticator app.</summary>
    public const string Issuer = "Starter";

    public static string Build(string email, string base32Secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(email);
        ArgumentException.ThrowIfNullOrEmpty(base32Secret);

        var issuer = Uri.EscapeDataString(Issuer);
        var label = $"{issuer}:{Uri.EscapeDataString(email)}";
        return $"otpauth://totp/{label}?secret={base32Secret}&issuer={issuer}";
    }
}
