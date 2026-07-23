using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Mfa;
using Starter.Identity.Passwords;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Login;

/// <summary>
/// Login: verifies the Argon2id credential (rehash-on-login
/// when parameters moved), then hands the proven user to the
/// method-agnostic SessionIssuer. One generic failure for every miss -
/// unknown email, missing password method, disabled password, wrong
/// password - with the Argon2 cost paid on all of them (timing
/// uniformity).
/// </summary>
internal sealed class LoginHandler(
    IdentityDbContext db,
    SessionIssuer sessions,
    MfaChallengeTokens mfaChallengeTokens,
    IPolicyDefaults policyDefaults,
    Clock clock)
{
    private static readonly Error InvalidCredentials = new(
        ErrorKind.Unauthorized,
        "auth.invalid_credentials",
        "The email or password is incorrect.");

    public async Task<Result<LoginOutcome>> HandleAsync(
        string email,
        string password,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        email = email.Trim();
        if (email.Length == 0 || password.Length == 0)
        {
            return InvalidCredentials;
        }

        var now = clock.UtcNow;

        // No transaction yet: these reads and the deliberately slow Argon2
        // calls below (Verify/VerifyDummy/Hash) run on every attempt,
        // including brute-force and enumeration traffic against unknown
        // accounts. Opening the transaction here would hold a pooled
        // connection for the full hash-computation duration on every one
        // of those requests - a connection-pool exhaustion risk under load.
        // The transaction opens inside the
        // SessionIssuer, only once a real credential has actually
        // verified, immediately before the writes that need its atomicity.
        var user = await db.Users.SingleOrDefaultAsync(
            candidate => candidate.Email == email && candidate.Status == UserStatus.Active,
            cancellationToken);
        var method = user is null
            ? null
            : await db.AuthMethods.SingleOrDefaultAsync(
                candidate => candidate.UserId == user.Id && candidate.Kind == AuthMethodKind.Password,
                cancellationToken);

        if (user is null || method?.PasswordHash is null || method.DisabledAt is not null)
        {
            // No usable credential: absent account, no password method, or
            // a password disabled by the OIDC claim (re-enabled
            // only by a reset). Burn the same Argon2 cost so
            // timing does not reveal which, and answer the same generic
            // 401 - a disabled-password hint would confirm the account
            // exists to anyone holding just the email. A Google-only account
            // has no password method, so it lands here and is never locked.
            PasswordHasher.VerifyDummy(password);
            return InvalidCredentials;
        }

        // TIMING-SAFE locked branch (role-templates-and-policy-defaults.md section
        // 4): when the credential is locked, STILL pay the full Argon2 cost before
        // returning the same generic 401. A locked account that early-returned
        // before hashing would be measurably FASTER than an unknown account or a
        // non-locked wrong password (both pay full Argon2), and that timing delta
        // is a real oracle revealing "this email exists and is currently locked".
        // The timing equalization outranks the CPU saving a lockout would otherwise
        // buy, and the answer carries no distinct "locked" hint (enumeration-safe;
        // a 423 with a retry-after is a documented section-7 grow-into).
        if (method.LockedUntil is DateTimeOffset lockedUntil && lockedUntil > now)
        {
            PasswordHasher.VerifyDummy(password);
            return InvalidCredentials;
        }

        if (!PasswordHasher.Verify(password, method.PasswordHash))
        {
            // Wrong password: increment the counter and conditionally lock in ONE
            // standalone ExecuteUpdateAsync with NO ambient transaction - LoginHandler
            // deliberately holds none at this point, to avoid pinning a pooled
            // connection during Argon2 under brute-force load. The threshold is
            // expressed IN the update (failed_attempts + 1 >= max), so concurrent
            // attempts serialize on the row and cannot lose an increment or undercount.
            var policy = await policyDefaults.GetAsync(cancellationToken);
            var maxAttempts = policy.LockoutMaxAttempts;
            DateTimeOffset? lockUntil = now + TimeSpan.FromSeconds(policy.LockoutDurationSeconds);
            await db.AuthMethods
                .Where(candidate => candidate.Id == method.Id)
                .ExecuteUpdateAsync(
                    set => set
                        .SetProperty(m => m.FailedAttempts, m => m.FailedAttempts + 1)
                        .SetProperty(
                            m => m.LockedUntil,
                            m => m.FailedAttempts + 1 >= maxAttempts ? lockUntil : m.LockedUntil),
                    cancellationToken);
            return InvalidCredentials;
        }

        // Successful verify: reset the lockout counter (auto-unlock made the attempt
        // possible again, or a stray failure never reached the threshold). Only when
        // there is something to clear, so the happy path adds no extra write.
        if (method.FailedAttempts != 0 || method.LockedUntil is not null)
        {
            await db.AuthMethods
                .Where(candidate => candidate.Id == method.Id)
                .ExecuteUpdateAsync(
                    set => set
                        .SetProperty(m => m.FailedAttempts, 0)
                        .SetProperty(m => m.LockedUntil, (DateTimeOffset?)null),
                    cancellationToken);
        }

        // MFA step-up (mfa-totp.md section 5): the password is proven, but a
        // CONFIRMED second factor turns login into a two-step exchange. Do NOT
        // issue a session here - return a short-lived challenge the mfa-verify
        // endpoint exchanges (with a TOTP or recovery code) for the real
        // session. A user without confirmed MFA logs in in one step, exactly as
        // before. Checked before the rehash so an MFA login stages no write.
        var mfaConfirmed = await db.MfaCredentials.AnyAsync(
            credential => credential.UserId == user.Id && credential.ConfirmedAt != null,
            cancellationToken);
        if (mfaConfirmed)
        {
            var challenge = mfaChallengeTokens.Mint(user.Id, now);
            return new LoginOutcome.MfaChallenge(challenge.Token, challenge.ExpiresInSeconds);
        }

        if (PasswordHasher.NeedsRehash(method.PasswordHash))
        {
            // The one moment the plaintext and the row meet with the
            // password proven: parameter upgrades ride logins.
            method.PasswordHash = PasswordHasher.Hash(password);
        }

        // The credential is proven: the issuer commits the new session row
        // and the rehash update tracked above in one transaction
        // (the same method-agnostic issuance Google
        // sign-in rides). Login is tenant-less: the session binds no tenant, so
        // the access token carries no tid and the caller selects a tenant next.
        var tokens = await sessions.IssueAsync(user, tenantId: null, deviceLabel, ipAddress, now, cancellationToken);
        return new LoginOutcome.Tokens(tokens);
    }
}
