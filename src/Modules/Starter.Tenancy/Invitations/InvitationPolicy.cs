using Starter.Tenancy.Domain;
using Starter.SharedKernel;

namespace Starter.Tenancy.Invitations;

/// <summary>
/// The invitation numbers in one place, plus the invitation-row factory. Tokens
/// are single-use with a 7-day window (a sane default, mirroring Identity's
/// verify-email policy). The raw token is returned to the caller for the email
/// channel and exists nowhere else - the row keeps only the hash.
/// </summary>
internal static class InvitationPolicy
{
    /// <summary>Invitation token TTL (7 days).</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromDays(7);

    /// <summary>
    /// Builds an invitations row for the tenant with a fresh hashed token. The
    /// raw token is returned alongside for the emailed link and is never
    /// persisted or logged. A scope-aware invite (section 16) also carries a
    /// <paramref name="workspaceId"/> + <paramref name="roleId"/> (both set
    /// together, both null for a plain tenant invite); the caller validates them
    /// before issuing.
    /// </summary>
    public static (Invitation Row, string RawToken) Issue(
        Guid tenantId,
        string email,
        string role,
        Guid invitedBy,
        DateTimeOffset now,
        Guid? workspaceId = null,
        Guid? roleId = null)
    {
        var rawToken = InvitationTokenSecrets.NewToken();
        var row = new Invitation
        {
            Id = Ids.NewId(now),
            TenantId = tenantId,
            Email = email,
            Role = role,
            TokenHash = InvitationTokenSecrets.Hash(rawToken),
            ExpiresAt = now + TokenLifetime,
            AcceptedAt = null,
            WorkspaceId = workspaceId,
            RoleId = roleId,
            InvitedBy = invitedBy,
            CreatedAt = now,
        };
        return (row, rawToken);
    }
}
