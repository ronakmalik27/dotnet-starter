namespace Starter.Platform.Auth;

/// <summary>
/// The one-time output of MFA enrollment (mfa-totp.md section 4): the
/// <c>otpauth://</c> provisioning URI the client renders as a QR code, and the
/// base32 secret for manual entry. Both are shown ONCE; the server keeps only
/// the encrypted secret. A platform contract type so the Identity module's Api
/// interface can return it without exporting a module type.
/// </summary>
/// <param name="OtpauthUri">The otpauth://totp/... provisioning URI (issuer and email percent-encoded).</param>
/// <param name="Secret">The base32-encoded shared secret, for manual authenticator entry.</param>
public sealed record MfaEnrollment(string OtpauthUri, string Secret);
