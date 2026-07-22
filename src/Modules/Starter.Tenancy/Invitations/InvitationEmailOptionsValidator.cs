using Microsoft.Extensions.Options;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// The {token}-placeholder rule for the invitation link template, richer than a
/// data annotation can express (mirrors Identity's EmailLinkTemplateValidator).
/// A template without the placeholder silently composes a link with no token, so
/// the invitee opens a page that can accept nothing. This fails fast at startup
/// (the options register with ValidateOnStart) with a message naming the config
/// key, rather than shipping dead links.
/// </summary>
internal sealed class InvitationEmailOptionsValidator : IValidateOptions<InvitationEmailOptions>
{
    private const string TokenPlaceholder = "{token}";

    public ValidateOptionsResult Validate(string? name, InvitationEmailOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return !string.IsNullOrEmpty(options.UrlTemplate)
            && options.UrlTemplate.Contains(TokenPlaceholder, StringComparison.Ordinal)
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(
                    $"{InvitationEmailOptions.SectionName}:UrlTemplate must contain the literal "
                    + $"\"{TokenPlaceholder}\" placeholder; without it the composed link has no token "
                    + "and cannot accept anything.");
    }
}
