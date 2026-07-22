namespace Starter.Tenancy.Domain;

/// <summary>
/// The tenant-slug shape rule in one place, shared by self-serve provisioning
/// and the tenant-settings update so the two can never diverge on what a legal
/// slug is. Letters (either case; citext makes uniqueness case-insensitive),
/// digits, and hyphens, within the DNS-label length ceiling. Case is deliberately
/// permissive so "Acme" and "acme" are both valid inputs that then collide on the
/// citext unique index.
/// </summary>
internal static class TenantSlugs
{
    /// <summary>The maximum slug length (a DNS label ceiling).</summary>
    public const int MaxLength = 63;

    public static bool IsValid(string slug)
    {
        if (slug.Length is 0 or > MaxLength)
        {
            return false;
        }

        foreach (var character in slug)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character != '-')
            {
                return false;
            }
        }

        return true;
    }
}
