namespace Starter.Identity.Domain;

/// <summary>
/// An identity.sso_login_states row: the SINGLE-USE, server-side record that binds
/// an SSO authorization request to its callback (sso-and-scim.md section 4.1). It
/// is a global Identity table (no tenant ownership, no RLS - like sessions and
/// users): it is keyed and looked up by the opaque <c>state</c> value, resolved
/// BEFORE any tenant context exists, and the tenant it carries is the ONLY source
/// of the tenant at callback time (never re-derived from the callback request or
/// the token's claims).
/// <para>
/// The raw <c>state</c> exists only in transit and in the caller's cookie; the row
/// stores a SHA-256 hex digest (the sessions.refresh_hash / one_time_tokens rule).
/// Single-use is enforced by <see cref="UsedAt"/> (set once at consumption); expiry
/// by <see cref="ExpiresAt"/>.
/// </para>
/// </summary>
internal sealed class SsoLoginState
{
    public required Guid Id { get; init; }

    /// <summary>SHA-256 hex of the opaque state value: the lookup key, unique in the live set.</summary>
    public required string StateHash { get; init; }

    /// <summary>The resolved tenant whose IdP the flow targets - the ONLY tenant source at callback.</summary>
    public required Guid TenantId { get; init; }

    /// <summary>The nonce bound into the authorize request; the id_token's nonce must echo it (replay defense).</summary>
    public required string Nonce { get; init; }

    /// <summary>The PKCE code_verifier for the S256 challenge sent to the IdP (code-interception defense).</summary>
    public required string CodeVerifier { get; init; }

    /// <summary>The redirect_uri sent to the IdP, replayed verbatim in the token exchange (OAuth requires the match).</summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The caller's user id when /start ran on an AUTHENTICATED in-app session (the
    /// link-into-my-account entry), else null (the unauthenticated email-routing
    /// entry). Used as the confirmedUserId in the linking decision, so an
    /// unauthenticated flow fails closed to "confirmation required" rather than
    /// auto-linking an email to a different existing account.
    /// </summary>
    public Guid? UserId { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set exactly once at consumption (single-use); never cleared.</summary>
    public DateTimeOffset? UsedAt { get; set; }

    public required DateTimeOffset CreatedAt { get; init; }
}
