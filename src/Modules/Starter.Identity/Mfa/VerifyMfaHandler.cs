using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Mfa;

/// <summary>
/// The second step of an MFA login (mfa-totp.md section 5): exchange a valid
/// challenge token plus a code for the real session. The challenge is
/// validated INSIDE the handler (its audience is rejected by the [Authorize]
/// pipeline). A code is EITHER a TOTP code (with the replay guard) OR a
/// single-use recovery code. Verifies are brute-force throttled PER USER with
/// the same lockout idiom the password path uses: N wrong codes lock the MFA
/// step, a fresh challenge does not reset the count, and a successful verify
/// resets it. Every failure is the same generic Unauthorized.
/// </summary>
internal sealed class VerifyMfaHandler(
    IdentityDbContext db,
    MfaChallengeTokens challengeTokens,
    MfaSecretProtector protector,
    SessionIssuer sessions,
    IPolicyDefaults policyDefaults,
    Clock clock)
{
    private static readonly Error Invalid = new(
        ErrorKind.Unauthorized,
        "auth.mfa_invalid",
        "The MFA challenge or code is not valid.");

    public async Task<Result<IssuedTokens>> HandleAsync(
        string challengeToken,
        string code,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(challengeToken);
        ArgumentNullException.ThrowIfNull(code);

        if (challengeToken.Length == 0 || code.Length == 0)
        {
            return Invalid;
        }

        var userId = await challengeTokens.ValidateAsync(challengeToken, cancellationToken);
        if (userId is null)
        {
            return Invalid;
        }

        var credential = await db.MfaCredentials.SingleOrDefaultAsync(
            candidate => candidate.UserId == userId.Value && candidate.ConfirmedAt != null,
            cancellationToken);
        if (credential is null)
        {
            return Invalid;
        }

        var now = clock.UtcNow;

        // Locked: refuse even a correct code, with the same generic answer, and
        // without incrementing (the timing-safe locked branch the password path
        // uses). A fresh challenge does not clear the lock or the count.
        if (credential.LockedUntil is DateTimeOffset lockedUntil && lockedUntil > now)
        {
            return Invalid;
        }

        var accepted = await TryTotpAsync(credential, code, now, cancellationToken)
            || await TryRecoveryCodeAsync(userId.Value, code, now, cancellationToken);
        if (!accepted)
        {
            await RecordFailedAttemptAsync(userId.Value, now, cancellationToken);
            return Invalid;
        }

        // The second factor is proven: issue the real session, tenant-less like
        // a normal login (the caller selects a tenant next, unchanged).
        var user = await db.Users.SingleAsync(candidate => candidate.Id == userId.Value, cancellationToken);
        return await sessions.IssueAsync(
            user, tenantId: null, deviceLabel, ipAddress, now, tenantSessionMaxSeconds: null, cancellationToken);
    }

    private async Task<bool> TryTotpAsync(
        MfaCredential credential,
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        byte[] secret;
        try
        {
            secret = Base32.Decode(protector.Unprotect(credential.SecretEncrypted));
        }
        catch (MfaSecretUnprotectException)
        {
            // A lost / rotated-away key ring makes TOTP unverifiable. Fall back
            // to the key-ring-independent recovery-code path rather than 500.
            return false;
        }

        if (!Totp.Verify(secret, code, Totp.CurrentStep(now), credential.LastStep, out var matchedStep))
        {
            return false;
        }

        // Advance the replay guard AND reset the lockout in one atomic update.
        // The condition re-checks the step so two racing verifies of the same
        // code cannot both mint a session from one step; the loser sees zero
        // rows and lands on the failed-attempt path.
        var updated = await db.MfaCredentials
            .Where(row => row.UserId == credential.UserId
                && (row.LastStep == null || row.LastStep < matchedStep))
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(row => row.LastStep, matchedStep)
                    .SetProperty(row => row.FailedAttempts, 0)
                    .SetProperty(row => row.LockedUntil, (DateTimeOffset?)null),
                cancellationToken);
        return updated == 1;
    }

    private async Task<bool> TryRecoveryCodeAsync(
        Guid userId,
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // A TOTP-shaped code (digits) normalizes to a short or empty base32
        // string that can never be a recovery code; skip the lookup rather than
        // hash an empty string.
        var normalized = RecoveryCodes.Normalize(code);
        if (normalized.Length == 0)
        {
            return false;
        }

        var hash = RecoveryCodes.Hash(normalized);

        // SINGLE atomic conditional consume: two concurrent submissions of the
        // same code cannot both pass and mint two sessions. Accept only when
        // exactly one live row flipped to used.
        var consumed = await db.MfaRecoveryCodes
            .Where(row => row.UserId == userId && row.CodeHash == hash && row.UsedAt == null)
            .ExecuteUpdateAsync(
                set => set.SetProperty(row => row.UsedAt, now),
                cancellationToken);
        if (consumed != 1)
        {
            return false;
        }

        // Reset the lockout on a successful verify.
        await db.MfaCredentials
            .Where(row => row.UserId == userId)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(row => row.FailedAttempts, 0)
                    .SetProperty(row => row.LockedUntil, (DateTimeOffset?)null),
                cancellationToken);
        return true;
    }

    private async Task RecordFailedAttemptAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var policy = await policyDefaults.GetAsync(cancellationToken);
        var maxAttempts = policy.LockoutMaxAttempts;
        DateTimeOffset? lockUntil = now + TimeSpan.FromSeconds(policy.LockoutDurationSeconds);

        // Increment and conditionally lock in one update; the threshold is
        // expressed IN the update so concurrent verifies serialize on the row.
        await db.MfaCredentials
            .Where(row => row.UserId == userId)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(row => row.FailedAttempts, row => row.FailedAttempts + 1)
                    .SetProperty(
                        row => row.LockedUntil,
                        row => row.FailedAttempts + 1 >= maxAttempts ? lockUntil : row.LockedUntil),
                cancellationToken);
    }
}
