using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.SharedKernel;

namespace Starter.Identity.Sso;

/// <summary>
/// The single-use, server-side SSO state store (sso-and-scim.md section 4.1): one
/// <c>identity.sso_login_states</c> row per authorize request, keyed by the SHA-256
/// of the opaque <c>state</c>, holding the resolved tenant, the nonce, the PKCE
/// code_verifier, the redirect_uri, and (when /start ran authenticated) the caller's
/// user id, with a short TTL. Consumption is a single atomic UPDATE that flips
/// <c>used_at</c> from null, so a replayed state can never be redeemed twice - the
/// row survives (consumed) for audit rather than being deleted.
/// </summary>
internal sealed class SsoStateStore(IdentityDbContext db, Clock clock)
{
    /// <summary>The authorize/callback round trip is short; a login should not idle for long.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    public async Task StoreAsync(
        string stateHash,
        Guid tenantId,
        string nonce,
        string codeVerifier,
        string redirectUri,
        Guid? callerUserId,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        db.SsoLoginStates.Add(new SsoLoginState
        {
            Id = Ids.NewId(now),
            StateHash = stateHash,
            TenantId = tenantId,
            Nonce = nonce,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            UserId = callerUserId,
            ExpiresAt = now.Add(Ttl),
            CreatedAt = now,
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Atomically consumes the state by hash: flips <c>used_at</c> from null when the
    /// row exists, is unused, and is unexpired, then returns it. A missing, expired,
    /// or already-consumed state returns null (all indistinguishable to the caller,
    /// which answers one generic failure).
    /// </summary>
    public async Task<SsoLoginState?> ConsumeAsync(string stateHash, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        // The single-use guard is one atomic statement: only one caller can move
        // used_at from null, so a concurrent replay of the same state loses the race
        // and sees zero rows affected.
        var affected = await db.SsoLoginStates
            .Where(state => state.StateHash == stateHash && state.UsedAt == null && state.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters.SetProperty(state => state.UsedAt, now), cancellationToken);
        if (affected == 0)
        {
            return null;
        }

        return await db.SsoLoginStates
            .AsNoTracking()
            .SingleOrDefaultAsync(state => state.StateHash == stateHash, cancellationToken);
    }
}
