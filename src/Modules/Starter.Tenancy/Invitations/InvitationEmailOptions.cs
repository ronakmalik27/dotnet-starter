using System.ComponentModel.DataAnnotations;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// Invitation email settings, bound from Tenancy:Invitations. The UrlTemplate is
/// the front-end accept page the invitee opens; its {token} placeholder is
/// replaced with the URL-encoded raw token when the email is composed. The
/// default points at a local SPA dev server; a real deployment overrides it with
/// its own web origin. The template is validated at startup: non-empty (data
/// annotation) and carrying the {token} placeholder (the custom
/// <see cref="InvitationEmailOptionsValidator"/>), exactly like the verify-email
/// and password-reset templates in Identity.
/// </summary>
internal sealed class InvitationEmailOptions
{
    public const string SectionName = "Tenancy:Invitations";

    /// <summary>
    /// The accept-invitation link template. The literal "{token}" is replaced
    /// with the URL-encoded invitation token.
    /// </summary>
    [Required]
    public string UrlTemplate { get; set; } = "https://localhost:3000/accept-invitation?token={token}";
}
