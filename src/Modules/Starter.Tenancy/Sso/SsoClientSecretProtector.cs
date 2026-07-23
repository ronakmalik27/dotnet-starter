using Microsoft.AspNetCore.DataProtection;

namespace Starter.Tenancy.Sso;

/// <summary>
/// Wraps the DataProtection protector for the per-tenant SSO client secret
/// (sso-and-scim.md sections 2, 3): <c>CreateProtector("identity.sso.client-secret.v1")</c>,
/// <c>Protect</c> on the admin config-save path, <c>Unprotect</c> when the SSO
/// config reader hands the decrypted secret to the code exchange. The secret must
/// be recoverable to POST it to the IdP token endpoint, so (unlike a password) it
/// is encrypted, not hashed; the key ring persists in
/// <c>platform.data_protection_keys</c>, so every replica decrypts with the same
/// keys. <see cref="IDataProtectionProvider"/> is a framework type registered
/// app-wide by <c>AddPlatformDataProtection</c>, so this stays module-boundary
/// clean.
/// <para>
/// <c>Unprotect</c> is wrapped so a lost or rotated-away key ring surfaces as a
/// distinct <see cref="SsoClientSecretUnprotectException"/> (the
/// WebhookSecretProtector / MfaSecretProtector pattern) and the config reader can
/// return "no usable config" rather than an unhandled 500 that would break the
/// callback.
/// </para>
/// </summary>
internal sealed class SsoClientSecretProtector
{
    private const string Purpose = "identity.sso.client-secret.v1";

    private readonly IDataProtector _protector;

    public SsoClientSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
    }

    /// <summary>Encrypts a raw client secret for storage. Never returns the raw secret.</summary>
    public string Protect(string rawSecret)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawSecret);
        return _protector.Protect(rawSecret);
    }

    /// <summary>
    /// Recovers a raw client secret from its ciphertext at code-exchange time.
    /// Throws <see cref="SsoClientSecretUnprotectException"/> when the key ring
    /// cannot decrypt it (a lost or rotated-away key), so the reader fails closed.
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
            throw new SsoClientSecretUnprotectException(
                "The SSO client secret could not be decrypted; the DataProtection key ring is unavailable or rotated away.",
                exception);
        }
    }
}

/// <summary>
/// An SSO client-secret decryption failure: the ciphertext exists but the key ring
/// cannot recover it. Caught distinctly by the config reader so a lost key ring
/// yields a controlled "no usable config" (a generic SSO failure) instead of an
/// unhandled 500.
/// </summary>
internal sealed class SsoClientSecretUnprotectException : Exception
{
    public SsoClientSecretUnprotectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
