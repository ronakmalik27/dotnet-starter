using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity.GoogleSignIn;

/// <summary>
/// FR-AUTH-03 Google sign-in: redeem the client's authorization code,
/// validate the ID token, then apply the SRS 5.3 / doc 10 4.5 linking
/// decision table and hand the resolved user to the method-agnostic
/// SessionIssuer - an OIDC login gets exactly the session a password
/// login gets (FR-AUTH-15 DR). Every code/token problem is one generic
/// Unauthorized: which check failed is not the caller's business.
/// </summary>
internal sealed class GoogleSignInHandler(
    IdentityDbContext db,
    GoogleCodeExchanger exchanger,
    GoogleIdTokenValidator validator,
    IOptions<GoogleOidcOptions> options,
    SessionIssuer sessions,
    OutboxWriter outbox,
    Clock clock)
{
    private static readonly Error SignInFailed = new(
        ErrorKind.Unauthorized,
        "auth.google_signin_failed",
        "Google sign-in failed; restart the sign-in flow.");

    /// <summary>
    /// The email is held by a VERIFIED account and the request proved no
    /// live session for it: never silently merge (doc 10 4.5). Google
    /// verified the caller's control of the email, so naming the conflict
    /// leaks nothing the caller does not already own (unlike password
    /// registration's no-enumeration posture). The endpoint layer maps
    /// this code to 409 starter:link-confirmation-required.
    /// </summary>
    private static readonly Error ConfirmationRequired = new(
        ErrorKind.Conflict,
        "auth.google_link_confirmation_required",
        "This email already belongs to an account. Sign in to that account first, then retry Google sign-in while signed in to confirm linking.");

    public async Task<Result<IssuedTokens>> HandleAsync(
        string code,
        string codeVerifier,
        string redirectUri,
        string nonce,
        Guid? confirmedUserId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(codeVerifier);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(nonce);

        if (!options.Value.IsConfigured)
        {
            // The endpoint layer maps this code to 501
            // starter:not-implemented (the doc 08 slug for a documented
            // capability this host has not enabled).
            return Result.Failure<IssuedTokens>(new Error(
                ErrorKind.Validation,
                "auth.google_not_configured",
                "Google sign-in is not configured on this host."));
        }

        var idToken = await exchanger.ExchangeAsync(code, codeVerifier, redirectUri, cancellationToken);
        if (idToken is null)
        {
            return SignInFailed;
        }

        var google = await validator.ValidateAsync(idToken, nonce, cancellationToken);
        if (google is null)
        {
            return SignInFailed;
        }

        if (!google.EmailVerified)
        {
            // SRS 5.3 keys every linking rule on a VERIFIED email; an
            // unverified Google email proves nothing about the address.
            return Result.Failure<IssuedTokens>(new Error(
                ErrorKind.Validation,
                "auth.google_email_unverified",
                "The Google account's email address is unverified; verify it with Google first."));
        }

        if (!EmailAddress.IsValid(google.Email))
        {
            return SignInFailed;
        }

        // Two attempts: concurrent first sign-ins with the same Google
        // account (or same email) race on the unique indexes; the loser
        // clears its stale tracked state and re-reads, landing on the
        // SignIn/claim path the winner created (the RegisterHandler
        // precedent, adapted - this endpoint must still issue tokens).
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0)
            {
                db.ChangeTracker.Clear();
            }

            try
            {
                return await ApplyLinkingDecisionAsync(
                    google, confirmedUserId, deviceLabel, ipAddress, cancellationToken);
            }
            catch (DbUpdateException exception) when (IsUniqueViolation(exception))
            {
                // Fall through to the retry.
            }
        }

        return SignInFailed;
    }

    private async Task<Result<IssuedTokens>> ApplyLinkingDecisionAsync(
        GoogleIdentity google,
        Guid? confirmedUserId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        // One transaction over the whole decision: the linking writes, the
        // outbox events (which must enqueue inside an open transaction,
        // doc 07 section 3), and the session row commit or roll back
        // together. Failure paths dispose without committing.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var linked = await db.AuthMethods.SingleOrDefaultAsync(
            method => method.Kind == AuthMethodKind.Google && method.ProviderSubject == google.Subject,
            cancellationToken);
        if (linked is not null)
        {
            // Keyed on the stable OIDC subject, never the email (a Google
            // account's email can change; its sub cannot).
            var owner = await db.Users.SingleAsync(user => user.Id == linked.UserId, cancellationToken);
            if (owner.Status != UserStatus.Active)
            {
                return SignInFailed;
            }

            return await IssueAndCommitAsync(owner);
        }

        var userHoldingEmail = await db.Users.SingleOrDefaultAsync(
            user => user.Email == google.Email, cancellationToken);
        if (userHoldingEmail is not null && userHoldingEmail.Status != UserStatus.Active)
        {
            return SignInFailed;
        }

        switch (GoogleLinking.Decide(subjectAlreadyLinked: false, userHoldingEmail, confirmedUserId))
        {
            case GoogleLinkAction.RegisterNewUser:
                {
                    var newUser = new User
                    {
                        Id = Ids.NewId(now),
                        Email = google.Email,
                        Status = UserStatus.Active,
                        // Born verified: Google proved the address (SRS 5.3).
                        EmailVerifiedAt = now,
                        TokenVersion = 1,
                        CreatedAt = now,
                    };
                    db.Users.Add(newUser);
                    AttachGoogleMethod(newUser.Id, google.Subject, now);
                    await outbox.EnqueueAsync(
                        db,
                        IdentityEvents.UserRegistered(newUser.Id, AuthMethodKind.Google, now),
                        cancellationToken);
                    return await IssueAndCommitAsync(newUser);
                }

            case GoogleLinkAction.ClaimUnverifiedAccount:
                {
                    // The OIDC-verified email claims the unverified password
                    // account (SRS 5.3). The password holder never proved this
                    // address, so the password credential is distrusted until
                    // a reset (FR-AUTH-05) re-establishes it: the row is
                    // disabled, never deleted (auditable, reversible), and the
                    // token-version bump revokes any refresh families it
                    // opened (doc 10 4.2's mass-revocation lever).
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
                    AttachGoogleMethod(user.Id, google.Subject, now);
                    await outbox.EnqueueAsync(
                        db, IdentityEvents.UserVerified(user.Id, now), cancellationToken);
                    await outbox.EnqueueAsync(
                        db,
                        IdentityEvents.AuthMethodLinked(
                            user.Id, AuthMethodKind.Google, passwordDisabled: true, now),
                        cancellationToken);
                    return await IssueAndCommitAsync(user);
                }

            case GoogleLinkAction.LinkConfirmed:
                {
                    // The request carried a live session for the very account
                    // holding the email: the explicit "confirm linking" step
                    // doc 10 4.5 demands. The password stays enabled - the
                    // account was verified, nothing is distrusted.
                    var user = userHoldingEmail!;
                    AttachGoogleMethod(user.Id, google.Subject, now);
                    await outbox.EnqueueAsync(
                        db,
                        IdentityEvents.AuthMethodLinked(
                            user.Id, AuthMethodKind.Google, passwordDisabled: false, now),
                        cancellationToken);
                    return await IssueAndCommitAsync(user);
                }

            case GoogleLinkAction.ConfirmationRequired:
                return ConfirmationRequired;

            default:
                return SignInFailed;
        }

        // The issuer joins the open transaction (it never commits one it
        // did not open); the commit here is the single point every
        // successful path funnels through.
        async Task<Result<IssuedTokens>> IssueAndCommitAsync(User user)
        {
            var tokens = await sessions.IssueAsync(user, deviceLabel, ipAddress, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return tokens;
        }
    }

    private void AttachGoogleMethod(Guid userId, string subject, DateTimeOffset now) =>
        db.AuthMethods.Add(new AuthMethod
        {
            Id = Ids.NewId(now),
            UserId = userId,
            Kind = AuthMethodKind.Google,
            ProviderSubject = subject,
            CreatedAt = now,
        });

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
