using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Identity.Domain;
using Starter.Identity.GoogleSignIn;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.Sso;

/// <summary>
/// The enterprise-SSO callback (sso-and-scim.md sections 4.2-4.4): look up the
/// single-use state record (the TENANT comes ONLY from it, never the callback
/// request or the token), RE-CHECK the config is enabled (an immediate kill
/// switch), exchange the code, and validate the id_token against the configured
/// issuer's JWKS (signature, iss, aud, lifetime, nonce, email_verified) - none of
/// these checks is skippable. Then JIT-match a returning user on
/// <c>(kind=sso, issuer, sub)</c> (the issuer is load-bearing: it blocks the
/// cross-IdP takeover), else link-by-email through the generalized
/// <see cref="GoogleLinking"/> table (using the state's caller id as the
/// confirmedUserId), else create; ensure a membership in the SSO tenant; and mint a
/// tenant-bound session applying the tenant's session-lifetime override.
/// </summary>
internal sealed class SsoCallbackHandler(
    IdentityDbContext db,
    SsoStateStore stateStore,
    ITenantSsoConfigReader configReader,
    SsoCodeExchanger exchanger,
    SsoIdTokenValidator validator,
    ITenantSsoProvisioner ssoProvisioner,
    ITenantSessionPolicyReader sessionPolicy,
    SessionIssuer sessions,
    OutboxWriter outbox,
    Clock clock)
{
    /// <summary>Every code/token/state problem is one generic failure: which check failed is not the caller's business.</summary>
    private static readonly Error SsoFailed = new(
        ErrorKind.Unauthorized,
        "auth.sso_failed",
        "SSO sign-in failed; restart the sign-in flow.");

    /// <summary>
    /// The SSO email belongs to a VERIFIED existing account and the unauthenticated
    /// redirect flow carried no signed-in confirmation: fail closed, never
    /// auto-link. Also the outcome when a second tenant's IdP asserts a victim's
    /// email - the account is not taken over.
    /// </summary>
    private static readonly Error ConfirmationRequired = new(
        ErrorKind.Conflict,
        "auth.sso_link_confirmation_required",
        "This email already belongs to an account. Sign in to that account first, then link SSO while signed in.");

    public async Task<Result<IssuedTokens>> HandleAsync(
        string state,
        string code,
        string? stateCookie,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        // CSRF double-submit: the state query param must match the HttpOnly state
        // cookie. The high-entropy state also keys the single-use server-side record
        // below, which is the authoritative guard.
        if (string.IsNullOrEmpty(state)
            || string.IsNullOrEmpty(code)
            || string.IsNullOrEmpty(stateCookie)
            || !string.Equals(state, stateCookie, StringComparison.Ordinal))
        {
            return SsoFailed;
        }

        var record = await stateStore.ConsumeAsync(SsoSecrets.Hash(state), cancellationToken);
        if (record is null)
        {
            // Missing, expired, or already-consumed (single-use): one generic failure.
            return SsoFailed;
        }

        // The tenant comes ONLY from the state record. Re-resolve the config and
        // RE-CHECK enabled==true here, so an admin disabling SSO mid-flow is an
        // immediate kill switch not bypassable by an in-flight code.
        var config = await configReader.GetConfigAsync(record.TenantId, cancellationToken);
        if (config is null || !config.Enabled)
        {
            return SsoFailed;
        }

        var idToken = await exchanger.ExchangeAsync(
            config.Issuer,
            config.ClientId,
            config.ClientSecret,
            code,
            record.CodeVerifier,
            record.RedirectUri,
            cancellationToken);
        if (idToken is null)
        {
            return SsoFailed;
        }

        var identity = await validator.ValidateAsync(
            idToken, config.Issuer, config.ClientId, record.Nonce, cancellationToken);
        if (identity is null)
        {
            return SsoFailed;
        }

        if (!identity.EmailVerified || !EmailAddress.IsValid(identity.Email))
        {
            // An unverified email must never link an account (the fail-closed reading).
            return SsoFailed;
        }

        var user = await ProvisionOrLinkUserAsync(config.Issuer, identity, record.UserId, cancellationToken);
        if (user.IsFailure)
        {
            return Result.Failure<IssuedTokens>(user.Error);
        }

        // Ensure a membership in the SSO tenant (JIT if absent, default member role) -
        // ONLY the tenant whose IdP just authenticated. Cross-schema, so it runs on
        // the bypass path through the platform port; idempotent for a returning user.
        await ssoProvisioner.EnsureMembershipAsync(record.TenantId, user.Value.Id, cancellationToken);

        // Mint the tenant-bound session applying the tenant's session-lifetime
        // override (sso-and-scim.md section 4.4): the SSO caller is already IN the
        // tenant, so this is not the tenant-less login path. The default IssueAsync
        // would pass null and silently give the platform default - a regression for
        // exactly the enterprise customer paying for SSO - so the override is
        // resolved and threaded through.
        var sessionMax = await sessionPolicy.GetSessionMaxSecondsAsync(record.TenantId, cancellationToken);
        var tokens = await sessions.IssueAsync(
            user.Value, record.TenantId, deviceLabel, ipAddress, clock.UtcNow, sessionMax, cancellationToken);
        return tokens;
    }

    private async Task<Result<User>> ProvisionOrLinkUserAsync(
        string issuer, SsoIdentity identity, Guid? confirmedUserId, CancellationToken cancellationToken)
    {
        // Two attempts: concurrent first sign-ins with the same account (or email)
        // race on the unique indexes; the loser clears its stale tracked state and
        // re-reads, landing on the returning-match path the winner created (the
        // GoogleSignInHandler precedent).
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0)
            {
                db.ChangeTracker.Clear();
            }

            try
            {
                return await ApplyLinkingDecisionAsync(issuer, identity, confirmedUserId, cancellationToken);
            }
            catch (DbUpdateException exception) when (IsUniqueViolation(exception))
            {
                // Fall through to the retry.
            }
        }

        return Result.Failure<User>(SsoFailed);
    }

    private async Task<Result<User>> ApplyLinkingDecisionAsync(
        string issuer, SsoIdentity identity, Guid? confirmedUserId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Returning user: match on (kind=sso, issuer, sub). The issuer is
        // load-bearing (section 2 CRITICAL) - the subject fast-path is trusted only
        // when the issuer that just validated the token matches the one stored, so
        // one tenant's IdP can never assert another's subject.
        var linked = await db.AuthMethods.SingleOrDefaultAsync(
            method => method.Kind == AuthMethodKind.Sso
                && method.Issuer == issuer
                && method.ProviderSubject == identity.Subject,
            cancellationToken);
        if (linked is not null)
        {
            var owner = await db.Users.SingleAsync(user => user.Id == linked.UserId, cancellationToken);
            if (owner.Status != UserStatus.Active)
            {
                return Result.Failure<User>(SsoFailed);
            }

            await transaction.CommitAsync(cancellationToken);
            return owner;
        }

        var userHoldingEmail = await db.Users.SingleOrDefaultAsync(
            user => user.Email == identity.Email, cancellationToken);
        if (userHoldingEmail is not null && userHoldingEmail.Status != UserStatus.Active)
        {
            return Result.Failure<User>(SsoFailed);
        }

        // The generalized account-linking decision table (GoogleLinking is a pure
        // function of the same three inputs - it is not Google-specific).
        switch (GoogleLinking.Decide(subjectAlreadyLinked: false, userHoldingEmail, confirmedUserId))
        {
            case GoogleLinkAction.RegisterNewUser:
                {
                    var newUser = new User
                    {
                        Id = Ids.NewId(now),
                        Email = identity.Email,
                        Status = UserStatus.Active,
                        // Born verified: the IdP asserted email_verified.
                        EmailVerifiedAt = now,
                        TokenVersion = 1,
                        CreatedAt = now,
                    };
                    db.Users.Add(newUser);
                    AttachSsoMethod(newUser.Id, issuer, identity.Subject, now);
                    await outbox.EnqueueAsync(
                        db, IdentityEvents.UserRegistered(newUser.Id, AuthMethodKind.Sso, now), cancellationToken);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return newUser;
                }

            case GoogleLinkAction.ClaimUnverifiedAccount:
                {
                    // The IdP-verified email claims an unverified password account:
                    // password login is distrusted until reset (row disabled, never
                    // deleted), and the token-version bump revokes any refresh
                    // families it opened.
                    var user = userHoldingEmail!;
                    var passwordMethods = await db.AuthMethods
                        .Where(method => method.UserId == user.Id
                            && method.Kind == AuthMethodKind.Password
                            && method.DisabledAt == null)
                        .ToListAsync(cancellationToken);
                    foreach (var method in passwordMethods)
                    {
                        method.DisabledAt = now;
                    }

                    user.EmailVerifiedAt = now;
                    user.TokenVersion++;
                    AttachSsoMethod(user.Id, issuer, identity.Subject, now);
                    await outbox.EnqueueAsync(db, IdentityEvents.UserVerified(user.Id, now), cancellationToken);
                    await outbox.EnqueueAsync(
                        db,
                        IdentityEvents.AuthMethodLinked(user.Id, AuthMethodKind.Sso, passwordDisabled: true, now),
                        cancellationToken);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return user;
                }

            case GoogleLinkAction.LinkConfirmed:
                {
                    // The request carried a live session for the very account holding
                    // the email: the explicit confirm-linking step. The password stays
                    // enabled - the account was verified, nothing is distrusted.
                    var user = userHoldingEmail!;
                    AttachSsoMethod(user.Id, issuer, identity.Subject, now);
                    await outbox.EnqueueAsync(
                        db,
                        IdentityEvents.AuthMethodLinked(user.Id, AuthMethodKind.Sso, passwordDisabled: false, now),
                        cancellationToken);
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return user;
                }

            case GoogleLinkAction.ConfirmationRequired:
                return Result.Failure<User>(ConfirmationRequired);

            default:
                return Result.Failure<User>(SsoFailed);
        }
    }

    private void AttachSsoMethod(Guid userId, string issuer, string subject, DateTimeOffset now) =>
        db.AuthMethods.Add(new AuthMethod
        {
            Id = Ids.NewId(now),
            UserId = userId,
            Kind = AuthMethodKind.Sso,
            Issuer = issuer,
            ProviderSubject = subject,
            CreatedAt = now,
        });

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
