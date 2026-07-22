using Microsoft.AspNetCore.DataProtection;

namespace Starter.Platform.Webhooks;

/// <summary>
/// Wraps the DataProtection protector used for webhook signing secrets (webhooks.md
/// section 5): <c>CreateProtector("webhooks.signing-secret.v1")</c>, <c>Protect</c> on
/// the request path (register / rotate), <c>Unprotect</c> on the worker at sign time.
/// The key ring persists in <c>platform.data_protection_keys</c>, so every replica and
/// every restart signs with the same keys.
/// <para>
/// <c>Unprotect</c> is wrapped so a lost or rotated-away key ring surfaces as a distinct
/// <see cref="WebhookSecretUnprotectException"/>, which the worker dead-letters
/// immediately rather than burning the whole retry budget on something that can never
/// succeed (webhooks.md sections 4, 5 - the key-ring single-point-of-failure).
/// </para>
/// </summary>
public sealed class WebhookSecretProtector
{
    private const string Purpose = "webhooks.signing-secret.v1";

    private readonly IDataProtector _protector;

    public WebhookSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
    }

    /// <summary>Encrypts a raw secret for storage. Never returns the raw secret.</summary>
    public string Protect(string rawSecret)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawSecret);
        return _protector.Protect(rawSecret);
    }

    /// <summary>
    /// Recovers a raw secret from its ciphertext at sign time. Throws
    /// <see cref="WebhookSecretUnprotectException"/> when the key ring cannot decrypt it
    /// (a lost or rotated-away key), so the worker can dead-letter distinctly.
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
            throw new WebhookSecretUnprotectException(
                "The webhook signing secret could not be decrypted; the DataProtection key ring is unavailable or rotated away.",
                exception);
        }
    }
}

/// <summary>
/// A signing-secret decryption failure: the ciphertext exists but the key ring cannot
/// recover it. Caught distinctly by the worker (webhooks.md section 4) so an operator
/// gets a clear signal instead of a silent retry-until-dead.
/// </summary>
public sealed class WebhookSecretUnprotectException : Exception
{
    public WebhookSecretUnprotectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
