namespace Starter.Platform.Auth;

/// <summary>
/// The success outcome of a self-serve signup. <see cref="Tokens"/> is non-null
/// on the fresh path (the new owner is auto-logged-in and the access token
/// carries the new tenant's <c>tid</c>); it is null when the email already
/// belonged to an account (no tenant was created - the enumeration-safe generic
/// success) or when the post-commit auto-login was skipped, so both collapse to
/// the same tokenless success shape and the response never leaks that the email
/// pre-existed. A slug conflict or a bad email / weak password is a failure on
/// the surrounding <c>Result</c>, not this success value.
/// </summary>
public sealed record SelfServeSignup
{
    private SelfServeSignup(IssuedTokens? tokens) => Tokens = tokens;

    /// <summary>The auto-login tokens (fresh path), or null (generic success).</summary>
    public IssuedTokens? Tokens { get; }

    /// <summary>The email already had an account: nothing created, no tokens.</summary>
    public static readonly SelfServeSignup ExistingAccount = new(tokens: null);

    /// <summary>A fresh tenant and owner were created; the owner is logged in.</summary>
    public static SelfServeSignup Created(IssuedTokens? tokens) => new(tokens);
}
