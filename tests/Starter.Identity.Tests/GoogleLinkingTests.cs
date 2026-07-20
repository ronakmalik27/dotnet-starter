using Shouldly;
using Starter.Identity.Domain;
using Starter.Identity.GoogleSignIn;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// The SRS 5.3 / doc 10 4.5 account-linking decision table, row by row:
/// claim an unverified password account, never silently merge into a
/// verified one, register when the email is free, plain sign-in when the
/// subject is already linked. The handler applies these decisions; the
/// integration suite proves them against the real schema.
/// </summary>
public class GoogleLinkingTests
{
    private static readonly DateTimeOffset SomeInstant = new(2026, 7, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void KnownSubject_IsAPlainSignIn_RegardlessOfEverythingElse()
    {
        // The stable OIDC sub is the linking key; once linked, email state
        // and confirmation are irrelevant.
        GoogleLinking.Decide(subjectAlreadyLinked: true, UnverifiedUser(), confirmedUserId: null)
            .ShouldBe(GoogleLinkAction.SignIn);
        GoogleLinking.Decide(subjectAlreadyLinked: true, userHoldingEmail: null, confirmedUserId: null)
            .ShouldBe(GoogleLinkAction.SignIn);
    }

    [Fact]
    public void FreeEmail_RegistersANewUser()
    {
        GoogleLinking.Decide(subjectAlreadyLinked: false, userHoldingEmail: null, confirmedUserId: null)
            .ShouldBe(GoogleLinkAction.RegisterNewUser);
    }

    [Fact]
    public void UnverifiedAccountHoldingTheEmail_IsClaimed()
    {
        // SRS 5.3: the OIDC-verified email claims the unverified password
        // account (the holder never proved the address; Google's user did).
        GoogleLinking.Decide(subjectAlreadyLinked: false, UnverifiedUser(), confirmedUserId: null)
            .ShouldBe(GoogleLinkAction.ClaimUnverifiedAccount);
    }

    [Fact]
    public void UnverifiedAccount_IsClaimedEvenWhenSomeoneElseIsSignedIn()
    {
        // A signed-in confirmation is only the VERIFIED-account gate; the
        // unverified claim does not consult it.
        var user = UnverifiedUser();

        GoogleLinking.Decide(subjectAlreadyLinked: false, user, confirmedUserId: Guid.NewGuid())
            .ShouldBe(GoogleLinkAction.ClaimUnverifiedAccount);
    }

    [Fact]
    public void VerifiedAccount_WithoutConfirmation_RequiresConfirmation_NeverMerges()
    {
        GoogleLinking.Decide(subjectAlreadyLinked: false, VerifiedUser(), confirmedUserId: null)
            .ShouldBe(GoogleLinkAction.ConfirmationRequired);
    }

    [Fact]
    public void VerifiedAccount_WithAConfirmationForADifferentAccount_StillRequiresConfirmation()
    {
        // Being signed in somewhere is not consent to link into someone
        // else's account: the session must belong to the email holder.
        GoogleLinking.Decide(subjectAlreadyLinked: false, VerifiedUser(), confirmedUserId: Guid.NewGuid())
            .ShouldBe(GoogleLinkAction.ConfirmationRequired);
    }

    [Fact]
    public void VerifiedAccount_WithItsOwnLiveSession_LinksAsASecondMethod()
    {
        var user = VerifiedUser();

        GoogleLinking.Decide(subjectAlreadyLinked: false, user, confirmedUserId: user.Id)
            .ShouldBe(GoogleLinkAction.LinkConfirmed);
    }

    private static User UnverifiedUser() => NewUser(emailVerifiedAt: null);

    private static User VerifiedUser() => NewUser(emailVerifiedAt: SomeInstant);

    private static User NewUser(DateTimeOffset? emailVerifiedAt) => new()
    {
        Id = Guid.NewGuid(),
        Email = "traveller@example.test",
        Status = UserStatus.Active,
        EmailVerifiedAt = emailVerifiedAt,
        TokenVersion = 1,
        CreatedAt = SomeInstant,
    };
}
