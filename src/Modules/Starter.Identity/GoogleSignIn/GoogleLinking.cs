using Starter.Identity.Domain;

namespace Starter.Identity.GoogleSignIn;

/// <summary>What a Google sign-in should do with the account state it found.</summary>
internal enum GoogleLinkAction
{
    /// <summary>The subject is already linked: plain sign-in.</summary>
    SignIn,

    /// <summary>No account holds this email: register a new user from the OIDC claims.</summary>
    RegisterNewUser,

    /// <summary>
    /// The email belongs to an UNVERIFIED password account: the
    /// OIDC-verified email claims it, and password login is disabled until
    /// reset (SRS 5.3).
    /// </summary>
    ClaimUnverifiedAccount,

    /// <summary>
    /// The email belongs to a verified account AND the request proved a
    /// live session for that same account: link as a second method.
    /// </summary>
    LinkConfirmed,

    /// <summary>
    /// The email belongs to a verified account and no signed-in
    /// confirmation was presented: never silently merge (doc 10 4.5) -
    /// surface the conflict.
    /// </summary>
    ConfirmationRequired,
}

/// <summary>
/// The SRS 5.3 / doc 10 4.5 account-linking decision table, as a pure
/// function so the unit suite can prove every row. Inputs: whether the
/// OIDC subject is already linked, the account currently holding the
/// email (if any), and the authenticated user the request carries (if
/// any). The caller has already established that the Google email is
/// verified - unverified Google emails never reach this table.
/// </summary>
internal static class GoogleLinking
{
    public static GoogleLinkAction Decide(bool subjectAlreadyLinked, User? userHoldingEmail, Guid? confirmedUserId)
    {
        if (subjectAlreadyLinked)
        {
            return GoogleLinkAction.SignIn;
        }

        if (userHoldingEmail is null)
        {
            return GoogleLinkAction.RegisterNewUser;
        }

        if (userHoldingEmail.EmailVerifiedAt is null)
        {
            return GoogleLinkAction.ClaimUnverifiedAccount;
        }

        return confirmedUserId == userHoldingEmail.Id
            ? GoogleLinkAction.LinkConfirmed
            : GoogleLinkAction.ConfirmationRequired;
    }
}
