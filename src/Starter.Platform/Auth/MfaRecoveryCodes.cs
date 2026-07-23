namespace Starter.Platform.Auth;

/// <summary>
/// The one-time set of MFA recovery codes (mfa-totp.md section 6), returned at
/// confirm and on regeneration. Each code is high-entropy (~80 bits), shown
/// ONCE, and stored only as a SHA-256 hash; a code is single-use at mfa-verify.
/// A platform contract type so the Identity module's Api interface can return
/// it without exporting a module type.
/// </summary>
/// <param name="Codes">The plaintext recovery codes, formatted for legibility, shown only here.</param>
public sealed record MfaRecoveryCodes(IReadOnlyList<string> Codes);
