using Microsoft.Extensions.Options;
using Starter.Identity.PasswordReset;

namespace Starter.Identity.Verification;

/// <summary>
/// A worked example of a custom IValidateOptions - a rule richer than a data
/// annotation can express. Both the verify-email and the password-reset link
/// templates MUST carry the literal "{token}" placeholder: a template without
/// it silently composes a link with no token, so the recipient opens a page
/// that can verify nothing. This fails fast at startup (the options are
/// registered with ValidateOnStart) with a message naming the offending
/// config key, rather than shipping dead links. One validator covers both
/// templates by implementing the interface twice.
/// </summary>
internal sealed class EmailLinkTemplateValidator
    : IValidateOptions<VerificationEmailOptions>, IValidateOptions<PasswordResetEmailOptions>
{
    private const string TokenPlaceholder = "{token}";

    public ValidateOptionsResult Validate(string? name, VerificationEmailOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return Validate(options.UrlTemplate, $"{VerificationEmailOptions.SectionName}:UrlTemplate");
    }

    public ValidateOptionsResult Validate(string? name, PasswordResetEmailOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return Validate(options.UrlTemplate, $"{PasswordResetEmailOptions.SectionName}:UrlTemplate");
    }

    private static ValidateOptionsResult Validate(string urlTemplate, string configKey) =>
        !string.IsNullOrEmpty(urlTemplate)
        && urlTemplate.Contains(TokenPlaceholder, StringComparison.Ordinal)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{configKey} must contain the literal \"{TokenPlaceholder}\" placeholder; "
                + "without it the composed link has no token and cannot verify anything.");
}
