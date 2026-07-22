using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
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
    Clock clock)
{
    private static readonly Error InvalidCredentials = new(
        ErrorKind.Unauthorized,
        "auth.invalid_credentials",
        "The email or password is incorrect.");

    public async Task<Result<IssuedTokens>> HandleAsync(
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
            // exists to anyone holding just the email.
            PasswordHasher.VerifyDummy(password);
            return InvalidCredentials;
        }

        if (!PasswordHasher.Verify(password, method.PasswordHash))
        {
            return InvalidCredentials;
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
        return await sessions.IssueAsync(user, tenantId: null, deviceLabel, ipAddress, now, cancellationToken);
    }
}
