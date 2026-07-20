namespace Starter.Platform.Auth;

/// <summary>
/// What a render-only tokenized GET may say about a verify-email token
/// (doc 10 4.7: the GET renders state, only the POST consumes). Lives in
/// the platform for the same reason as <see cref="IssuedTokens"/>: the
/// Identity module exports no types beyond its Api interface and bootstrap
/// class (ModuleSurfaceTests). Unknown tokens are a NotFound failure, not
/// a status: a URL that never existed has no state to render.
/// </summary>
public enum VerificationTokenStatus
{
    /// <summary>Live: unused and unexpired; the page renders the confirm POST.</summary>
    Valid,

    /// <summary>Past its 24-hour TTL and never used (FR-AUTH-02); the page offers resend.</summary>
    Expired,

    /// <summary>Already consumed; the page points to sign-in.</summary>
    Used,
}
