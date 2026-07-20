using System.Net.Mail;

namespace Starter.Identity.Domain;

/// <summary>
/// Registration-time email shape check: RFC-parseable, a dotted domain,
/// and within the RFC 5321 length ceiling. Deliverability is proven by the
/// verification mail, not by parsing harder here (industry position:
/// validate loosely, verify by sending).
/// </summary>
internal static class EmailAddress
{
    private const int MaximumLength = 254;

    public static bool IsValid(string email) =>
        !string.IsNullOrWhiteSpace(email)
        && email.Length <= MaximumLength
        && MailAddress.TryCreate(email, out var parsed)
        // MailAddress normalizes the domain to lowercase, so an
        // ordinal comparison would reject "user@Example.com" even
        // though identity.users.email is citext (case-insensitive
        // storage) - the shape check must agree.
        && string.Equals(parsed.Address, email, StringComparison.OrdinalIgnoreCase)
        && parsed.Host.Contains('.', StringComparison.Ordinal);
}
