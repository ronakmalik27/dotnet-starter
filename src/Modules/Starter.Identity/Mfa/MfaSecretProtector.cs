using Microsoft.AspNetCore.DataProtection;

namespace Starter.Identity.Mfa;

/// <summary>
/// Wraps the DataProtection protector for the TOTP shared secret (mfa-totp.md
/// sections 1, 3): <c>CreateProtector("identity.mfa.secret.v1")</c>,
/// <c>Protect</c> on enroll, <c>Unprotect</c> at verify time. The secret must
/// be recoverable to compute a TOTP code, so (unlike a password) it is
/// encrypted, not hashed; the key ring persists in
/// <c>platform.data_protection_keys</c>, so every replica decrypts with the
/// same keys. <see cref="IDataProtectionProvider"/> is a framework type
/// registered app-wide by <c>AddPlatformDataProtection</c>, so this stays
/// module-boundary clean.
/// <para>
/// <c>Unprotect</c> is wrapped so a lost or rotated-away key ring surfaces as
/// a distinct <see cref="MfaSecretUnprotectException"/> (the
/// WebhookSecretProtector pattern) and the verify path returns a controlled
/// error with the recovery-code fallback, NOT an unhandled 500.
/// </para>
/// </summary>
internal sealed class MfaSecretProtector
{
    private const string Purpose = "identity.mfa.secret.v1";

    private readonly IDataProtector _protector;

    public MfaSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
    }

    /// <summary>Encrypts the base32 secret for storage. Never returns it in the clear.</summary>
    public string Protect(string base32Secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(base32Secret);
        return _protector.Protect(base32Secret);
    }

    /// <summary>
    /// Recovers the base32 secret from its ciphertext at verify time. Throws
    /// <see cref="MfaSecretUnprotectException"/> when the key ring cannot
    /// decrypt it, so the verify path can fall back to a recovery code rather
    /// than 500.
    /// </summary>
    public string Unprotect(string ciphertext)
    {
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        try
        {
            return _protector.Unprotect(ciphertext);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new MfaSecretUnprotectException(
                "The MFA secret could not be decrypted; the DataProtection key ring is unavailable or rotated away.",
                exception);
        }
    }
}

/// <summary>
/// A TOTP-secret decryption failure: the ciphertext exists but the key ring
/// cannot recover it. Caught distinctly by the verify path (mfa-totp.md section
/// 3) so a lost key ring yields a controlled error with the recovery-code
/// fallback instead of an unhandled 500.
/// </summary>
internal sealed class MfaSecretUnprotectException : Exception
{
    public MfaSecretUnprotectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
