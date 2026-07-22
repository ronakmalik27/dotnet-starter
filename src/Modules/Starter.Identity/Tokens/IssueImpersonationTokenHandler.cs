using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Tokens;

/// <summary>
/// Mints the impersonation access token (multi-tenancy.md section 7), called by
/// the platform-admin endpoint AFTER the Tenancy control plane has committed the
/// grant row and its ImpersonationStarted event - so no token is ever minted
/// without its audit record. It loads the SUBJECT (the target user, or the
/// acting admin when there is no target user) to read the current token version,
/// so the token validates exactly like a normal one, then mints a short token
/// carrying tid (the target tenant), imp / impgrant (the acting admin and grant),
/// and exp = the grant's absolute expiry. No refresh token and no session row:
/// impersonation is not refreshable. An absent or inactive subject is a generic
/// Unauthorized.
/// </summary>
internal sealed class IssueImpersonationTokenHandler(
    IdentityDbContext db,
    AccessTokenIssuer accessTokens,
    Clock clock)
{
    private static readonly Error SubjectUnavailable = new(
        ErrorKind.Unauthorized,
        "auth.impersonation_subject_unavailable",
        "No active account is available to impersonate.");

    public async Task<Result<TenantAccessToken>> HandleAsync(
        Guid subjectUserId,
        Guid tenantId,
        Guid actingAdminUserId,
        Guid grantId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var version = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == subjectUserId && user.Status == UserStatus.Active)
            .Select(user => (int?)user.TokenVersion)
            .SingleOrDefaultAsync(cancellationToken);
        if (version is null)
        {
            return SubjectUnavailable;
        }

        var accessToken = accessTokens.IssueImpersonation(
            subjectUserId, tenantId, version.Value, actingAdminUserId, grantId, now, expiresAt);

        // The token and the grant die together: report the remaining lifetime,
        // never more than the 15-minute cap the grant window already enforced.
        var expiresIn = (int)Math.Max(0, (expiresAt - now).TotalSeconds);
        return new TenantAccessToken(accessToken, expiresIn);
    }
}
