# Enterprise SSO (OIDC) and SCIM provisioning

Status: DESIGN (proposed). The eleventh SaaS grow-into feature (multi-tenancy.md
section 21: "SSO (SAML / OIDC) and SCIM provisioning: a per-tenant identity-provider
config; SCIM maps directory groups to teams and roles"). Docs-first: nothing here is
built until this revision is reviewed.

**Built as an integration SEAM, deliberately, not a from-scratch protocol stack.**
Hand-rolling a full SAML stack or a complete SCIM 2.0 server is below-par AND the
most expensive option (a well-known footgun class: XML signature-wrapping in SAML,
the sprawl of SCIM filtering/PATCH). The right engineering call for a starter is a
CORRECT minimal path over a standards-compliant OIDC IdP configured per tenant, plus
a SCIM 2.0 Users skeleton, with the full protocol surface documented as grow-into.
OIDC (not SAML) is the built protocol: it is the modern default, and it reuses the
Identity module's existing Google-OIDC machinery (code exchange, id_token validation,
account-linking) generalized to a configurable issuer. SAML is a documented grow-into
(section 8).

## 1. The decision, up front

- **SSO is per-tenant enterprise login: a tenant configures its own OIDC IdP** (Okta,
  Azure AD / Entra, Google Workspace, Auth0) and its members sign in through it. This
  is distinct from the app's own first-party Google sign-in (a consumer convenience);
  enterprise SSO is a tenant's corporate directory federating INTO the tenant.
- **The OIDC flow reuses the existing Google-OIDC shape, generalized.** The Identity
  module already does a client-driven authorization-code exchange + id_token
  validation (issuer / audience / signature / lifetime) + an account-linking decision
  table (`GoogleLinking`). The SSO seam is that same flow with the issuer, JWKS,
  client id, and client secret read from a PER-TENANT config instead of a single
  hardcoded Google. The security-critical validation (verified issuer, audience =
  the tenant's client id, signature against the IdP's JWKS, `nonce` + `state`) is NOT
  hand-waved by "seam" - it is the part that must be exactly right, and it is
  specified in section 4.
- **JIT provisioning links or creates the user INTO the configured tenant.** On first
  SSO sign-in, the verified email resolves to an existing global user (link a new
  auth method) or a new user (create), and a MEMBERSHIP in the SSO tenant is
  provisioned just-in-time. A user is only ever provisioned into the tenant whose IdP
  authenticated them - never an arbitrary tenant.
- **SCIM is the directory's push channel; SSO is the login pull.** They are
  independent and either can ship without the other. SCIM (System for Cross-domain
  Identity Management, RFC 7643/7644) lets the tenant's IdP PROVISION and, crucially,
  DEPROVISION members from the directory side - and a SCIM deprovision drives the same
  member-deactivation / offboarding path an admin removal does (multi-tenancy.md
  section 20). The seam is a SCIM 2.0 Users skeleton (the standard resource shape +
  core CRUD + deactivate), per-tenant-token authenticated; Groups-to-teams, PATCH,
  and filtering are grow-into (section 8).

## 2. Data model

`tenancy.sso_configs`, tenant-owned, RLS (one per tenant): the per-tenant OIDC IdP.

| column | type | notes |
|---|---|---|
| `tenant_id` | uuid | PK (one IdP per tenant) |
| `issuer` | text not null | the IdP's OIDC issuer (authority) |
| `client_id` | text not null | the app's client id AT the IdP (the id_token audience) |
| `client_secret_encrypted` | text not null | the client secret, DataProtection-encrypted (`[Sensitive]`, never exported - data-export-and-erasure.md section 8) |
| `enabled` | boolean not null | SSO off until an admin turns it on |
| `created_at` / `updated_at` | timestamptz not null | |

`identity.auth_methods` gains an `issuer text null` column, and its returning-user
match becomes COMPOUND. **This is a CRITICAL auth-boundary fix, not a convenience.**
Today the match is `(kind, provider_subject)` with a unique index on those two - safe
for `kind=google` ONLY because Google is a single globally-trusted issuer whose `sub`
namespace is Google's own and unforgeable. A per-tenant SSO IdP makes `kind=sso`
SHARED across every tenant's independently-configured, tenant-controlled IdP, so
matching a returning user on `(kind=sso, sub)` WITHOUT the issuer is a cross-IdP
account takeover: a malicious tenant admin configures their own OIDC IdP (their keys,
their issuer) and mints a token asserting a VICTIM's known `sub` - every per-token
check (iss/aud/sig/nonce) passes because it is all under their control, and the
issuer-less lookup signs them in AS the victim, skipping the email-based linking
table entirely. So: add `issuer`, make the SSO unique index `(kind, issuer,
provider_subject)`, and match the returning SSO user on `(kind=sso, issuer, sub)`
where `issuer` is the one that just validated the token. (It is also the functional
fix: two tenants' IdPs assigning the same `sub` to two different people would
otherwise collide on the old two-column unique index and fail provisioning.) The
Google match keeps its existing `(kind, provider_subject)` shape (single issuer).

`tenancy.sso_domain_claims`, tenant-owned, RLS: the routing domains, ONE ROW PER
DOMAIN with a GLOBAL unique index on the normalized domain (`domain citext`,
`tenant_id`, `verified_at`). A per-tenant `allowed_domains` array (the earlier shape)
has NO cross-tenant exclusivity, so two tenants could both claim `contoso.com` and a
`contoso.com` login would route to whichever config matched first - possibly an
attacker's IdP (credential phishing). A global unique index on the domain makes a
duplicate claim a CONSTRAINT VIOLATION the operator-approval process cannot silently
miss (section 3), not merely a policy expectation.

`tenancy.scim_tokens`, tenant-owned, RLS: the per-tenant SCIM bearer credential.

| column | type | notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid not null | the RLS discriminator |
| `token_hash` | text not null | SHA-256 of the SCIM bearer token (`scim_`-prefixed, 256-bit, shown once), globally-unique index for the tenant-less lookup - the API-key pattern (service-accounts.md); `[Sensitive]` |
| `token_prefix` | text not null | the first chars of the raw token, in clear for display (never the secret), replaced on rotate |
| `created_by` / `created_at` | | |
| `expires_at` | timestamptz null | optional expiry; a token past it fails to resolve |
| `revoked_at` | timestamptz null | rotate/revoke |

`tenancy.memberships` gains a nullable `scim_external_id text` column: the IdP's SCIM
`externalId` for a directory-provisioned member, round-tripped on GET/PUT so a SCIM
client's reconciliation lines up. It is per-(tenant, user), so it belongs on the
membership, not the global user, and it is not a secret (it rides the membership DSAR
export like the other columns).

- Both are tenant-owned under RLS (a tenant's SSO config and SCIM token are its own).
  The `client_secret` and `token_hash` are the two `[Sensitive]` columns this
  increment adds - excluded from the data export and redacted in the erasure snapshot,
  which the completeness test (data-export-and-erasure.md section 8) enforces
  automatically once tagged. The erasure declarations gain both tables.

## 3. Config and domain routing

- A tenant admin manages the SSO config, its domain claims, and the SCIM token
  through the tenant-admin API, gated `RequirePermission(settings:manage)` (the
  enterprise-SSO setup is an admin act; no new permission atom). Set
  issuer/client-id/secret/domains, enable/disable, rotate the SCIM token. The client
  secret is write-only (set, never read back; encrypted at rest).
- **The `issuer` MUST be HTTPS**, rejected at config-save time. The existing
  `GoogleOidcMetadata` allows plain http only for the integration suite's loopback
  fake issuer; a free-text per-tenant issuer must not inherit that escape hatch - a
  plain-http issuer weakens the JWKS/discovery fetch to network tampering. Reject a
  non-`https://` issuer at the `settings:manage` save endpoint (the local-dev loopback
  exception stays confined to the test host).
- **Domain routing (SP-initiated).** A login begins with an email; its domain is
  matched - EXACT, case-insensitive equality on the full domain, never a
  suffix/substring test (or `notcontoso.com` would match an approved `contoso.com`) -
  against `sso_domain_claims` to find the tenant whose IdP owns it, then the user is
  redirected to that IdP. A domain claim is a takeover vector (a tenant claiming
  `gmail.com` would capture every Google user), defended by TWO controls: the GLOBAL
  unique index on the normalized domain (section 2) makes a domain claimable by at
  most ONE tenant, and a claim only ROUTES once `verified_at` is set - by
  operator approval, or a documented DNS-TXT domain-verification (section 8). An
  unverified or unclaimed domain does not route. Both gates are load-bearing.

## 4. The OIDC sign-in flow (the security-critical part)

Authorization-code flow, per tenant, reusing the Google-OIDC validator generalized:

1. **Initiate** (`GET /api/v1/auth/sso/start?email=` or `?tenantId=`): resolve the
   tenant's enabled SSO config; build the IdP authorize URL with `client_id`,
   `redirect_uri`, `scope=openid email profile`, a random `state` (CSRF), a random
   `nonce` (replay), and an S256 PKCE `code_challenge` (defense-in-depth against
   code interception, OAuth 2.1 / what the SPA's Google flow already does). Store a
   SINGLE-USE server-side record keyed by `state`, holding: the resolved TENANT_ID,
   the `nonce`, the PKCE `code_verifier`, a short TTL, and - when `/start` is called
   from an AUTHENTICATED in-app session (the link-into-my-account entry, vs the
   unauthenticated email-routing entry) - the caller's user id. The `state` cookie is
   `HttpOnly` + `Secure` + `SameSite=Lax` (Lax survives the top-level GET redirect
   back from the IdP; Strict would silently drop it and break every login). Redirect.
2. **Callback** (`GET /api/v1/auth/sso/callback?code=&state=`): look up the
   server-side `state` record (reject a missing/expired/mismatched one, single-use);
   **the TENANT_ID comes ONLY from that record, never re-derived from the callback
   request or the token's claims** (an attacker-tampered callback param must not pick
   the config). Re-resolve the tenant's SSO config and RE-CHECK `enabled == true` at
   THIS point (so an admin disabling SSO mid-incident is an immediate kill switch, not
   bypassable by an in-flight code). Exchange `code` at the IdP token endpoint using
   `client_id` + the decrypted `client_secret` + the PKCE `code_verifier` (over
   HTTPS), and VALIDATE the returned `id_token`:
   - signature against the IdP's JWKS (fetched from the CONFIGURED issuer's discovery
     document, cached; the `GoogleIdTokenValidator` / `ConfigurationManager` shape),
   - `iss` == the tenant's configured `issuer` (EXACT match - this pins the token to
     THIS tenant's IdP),
   - `aud` == the tenant's `client_id`,
   - `exp` / `nbf` current, and `nonce` == the one in the state record,
   - `email_verified` == true (an unverified email must never link an account - the
     fail-closed reading the Google flow already uses).
   Any failure is a generic SSO error; none of these checks is skippable.
3. **JIT provision / link** into the SSO tenant. First match a RETURNING user by
   `(kind=sso, issuer, sub)` - the issuer is load-bearing (section 2 CRITICAL): the
   subject fast-path is only trusted when the issuer that just validated the token
   matches the one stored on the auth method, so one tenant's IdP can never assert
   another's subject. Otherwise resolve by verified `email` through the account
   -linking decision table (generalize `GoogleLinking`), using the state record's
   caller user id as `confirmedUserId` when present (an unauthenticated redirect flow
   has none, so a match-by-email-to-a-different-existing-account fails CLOSED to
   "confirmation required", never auto-links). A brand-new email creates a user. Then
   ensure a MEMBERSHIP in the SSO tenant (create it JIT if absent, default member
   role). The user is provisioned ONLY into the tenant whose IdP just authenticated
   them; linking an SSO method to an existing global user grants access to THIS tenant
   only (a membership is per-tenant - no other tenant's access is affected).
4. **Mint the session** for that tenant (the tid token), tenant-bound, via
   `SessionIssuer` - the caller is already in the tenant, unlike first-party login
   which is tenant-less then selects. The mint MUST apply the tenant's
   session-lifetime override: resolve `ITenantSessionPolicyReader` (increment 16b) for
   the tenant and thread it through, exactly as `SelectTenantHandler` does. The
   default `SessionIssuer.IssueAsync` path passes `tenantSessionMaxSeconds: null` and
   would silently give SSO logins the PLATFORM default even when the tenant tightened
   it - a regression precisely for the enterprise customer paying for SSO, so the SSO
   callback must not use that default path unchanged. SSO bypasses MFA only if the IdP
   asserted it (an `amr` grow-into); by default MFA (increment 17) still applies if the
   user enrolled it - documented.
- A new SSO `auth_methods` kind (`sso`) stores the `issuer` (the new column, section
  2) + `provider_subject` (the stable IdP `sub`), matched on `(kind, issuer, sub)`
  (never on email alone - email can change at the IdP, and issuer-less matching is the
  section-2 CRITICAL takeover).

## 5. SCIM 2.0 provisioning (the skeleton)

- **The dedicated SCIM auth scheme, CONFINED to `/scim/v2`.** An `Authorization:
  Bearer scim_...` token resolves (by `token_hash`, tenant-less lookup like the API
  key) to its tenant, and every SCIM operation runs scoped to THAT tenant on the
  RLS request path (the resolved `tid` is bound by `TenantResolutionMiddleware`, so
  the Users CRUD rides the normal RLS-bound path; only the token RESOLVER is a
  tenant-less bypass slice). A `scim_` bearer must authenticate ONLY `/scim/v2` and
  must NEVER become a general tenant-admin credential. Four controls enforce that
  together: (1) the forwarding selector routes a request to the SCIM scheme ONLY when
  it carries the `scim_` bearer shape AND its path starts with `/scim/v2` - a `scim_`
  bearer on any other path falls through to JWT and gets a 401; (2) the `/scim/v2`
  endpoint group is pinned with an authorization policy that accepts ONLY the SCIM
  scheme, even if the selector were ever misconfigured; (3) the SCIM handler mints a
  NON-resolving principal - `tid` (the resolved tenant), a distinct `pt=scim`, and a
  synthetic `sub` that corresponds to NO real user - so it never resolves through the
  RBAC permission/role resolvers, and possession of the `tid`-scoped bearer IS the
  authority for the SCIM surface (the Users routes carry no `RequirePermission`); (4)
  a regression test proves a valid SCIM token gets 401/403 on non-SCIM tenant routes
  (including `/api/v1/tenant/notifications`) and works on `/scim/v2/Users`.
- The global user is resolved-or-created through a Platform port,
  `IUserProvisioner` (Identity implements, Tenancy consumes - the
  `ITenantSsoProvisioner` bridge in reverse, so Identity and Tenancy never reference
  each other). **A SCIM-provisioned user is born UNVERIFIED and passwordless.** That
  is load-bearing: the tenant member's first real SSO login then claims the shell
  through the existing account-linking table (`ClaimUnverifiedAccount`) with no new
  code path, whereas a user born verified would resolve to `ConfirmationRequired`
  (409) and lock the member out of their own shell.
- Core operations mapping SCIM Users to tenant memberships:
  - `POST /Users` (provision): resolve-or-create the global user, then ensure a member
    of the token's tenant (default member role). Idempotent on `userName` (the email):
    a repeat returns the existing member with no duplicate; `externalId` round-trips on
    a genuine create. Emits `tenancy.membership.created` only on a fresh membership.
  - `GET /Users/{id}` and `GET /Users?filter=userName eq "..."` (the ONE filter SCIM
    clients require for reconciliation; broader filtering is grow-into): return the
    SCIM User resource for a member of the token's tenant. A user who is a member of
    ANOTHER tenant only is invisible under RLS and reads as 404 (no cross-tenant
    confirmation). Any other filter is an empty ListResponse (never a general parser).
  - `PUT /Users/{id}` and the `active` flag: `active=false` DEACTIVATES the member -
    a genuine SOFT status flip (Active -> Suspended) preserving the row, role,
    role assignments, and team memberships, which is the WHOLE POINT of SCIM (a
    directory offboard immediately cuts tenant access - the authorization resolvers
    already fail closed on any non-Active status). `active=true` reactivates. Only
    `active` is honored; a PUT never changes the email (it would re-key the global
    user) and never processes `roles` / `groups` / `entitlements`.
  - `DELETE /Users/{id}`: deactivate (soft, -> Suspended), NOT a hard delete (audit).
  - Suspend and reactivate are idempotent no-ops when already in the target state
    (directory syncs retry relentlessly), and suspend is guarded against the tenant's
    last owner (a SCIM error, never a 500 or a lockout).
- The response bodies are the standard SCIM 2.0 `urn:ietf:params:scim:schemas:core:2.0:User`
  shape (`schemas`, `id` = our global user guid, `userName`, `active`, `emails`,
  `externalId`, `meta`) so a real Okta/Azure-AD SCIM client interoperates, and errors
  use the SCIM error envelope (`urn:ietf:params:scim:api:messages:2.0:Error`), a
  DELIBERATE deviation from the app's RFC 9457 shape scoped ONLY to `/scim/v2`.
  `PATCH` (partial ops), `/Groups` (mapped to teams), bulk, discovery, complex
  filtering, and SCIM-driven role assignment are documented grow-into (section 8) - the skeleton is
  the resource shape + the CRUD + the deactivate-drives-offboarding link, which is the
  load-bearing behavior. An IdP's `roles` / `groups` / `entitlements` attributes are
  IGNORED by construction (the request DTO does not bind them), closing a
  privilege-escalation vector smuggled through a deferred feature.
- The SCIM token itself is managed through the tenant-admin API
  (`/api/v1/tenant/scim/tokens`), gated `RequirePermission(settings:manage)` - the same
  enterprise-integration admin surface as the SSO config, no new permission atom:
  create (mint + return the raw token ONCE), list (prefixes + metadata only, never the
  hash), rotate (mint a new secret on the same row, the old stops resolving), and
  revoke (idempotent). Create and rotate are refused under an impersonation token
  (minting a standing bearer under a support session is a persistence vector); the same
  hardening is applied to the existing service-account create/rotate in the same pass.

## 6. Events and audit

- SSO config changes are a tenant-admin action on the existing settings/audited
  surface, emitting the dedicated `tenancy.sso.configured` tenant-scoped event on the
  deliverable catalogue (audited + webhook-deliverable). An SSO SIGN-IN reuses the
  existing session/login events; a JIT provision emits `tenancy.membership.created`.
- SCIM adds THREE tenant-scoped events to the deliverable catalogue (audited AND
  webhook-deliverable): `tenancy.scim.token_rotated` (create/rotate of a SCIM bearer,
  no secret on the payload), `tenancy.member.suspended` (a deprovision - PUT
  active=false or DELETE), and `tenancy.member.reactivated` (PUT active=true). A fresh
  provision emits the existing `tenancy.membership.created`. A directory offboard
  cutting tenant access is exactly the change a security team wants on the record, so
  suspend/reactivate are their own events rather than folded into the removal event.

## 7. Placement and deletability

- The SSO config + flow live in the Identity module (it owns auth) reading a
  per-tenant config through a Platform port (the `ITenantSessionPolicyReader` seam
  from increment 16b - Identity must not reference Tenancy directly; a new
  `ITenantSsoConfigReader` Platform port that Tenancy implements). The SCIM endpoints
  live in the Api layer over the Tenancy membership surface, and the SCIM Users CRUD
  reaches Identity ONLY through the `IUserProvisioner` / `IUserDirectory` Platform
  ports (Identity implements, Tenancy consumes), so the module boundary holds.
- Deletable: drop `tenancy.sso_configs` + `tenancy.scim_tokens` + their migrations, the
  `memberships.scim_external_id` column, the SSO start/callback endpoints + the `sso`
  auth-method kind, the SCIM endpoints + auth scheme + token-management surface, the
  `IUserProvisioner` port, and the erasure-declaration + `[Sensitive]` entries for both
  new secret columns. First-party login (password / Google) is untouched.

## 8. Deferred (documented grow-into, not built)

- **SAML 2.0** as a second SSO protocol (the enterprise laggard's format), with its
  own signature-validation care - the reason OIDC is built first.
- OIDC IdP metadata AUTO-DISCOVERY (`.well-known/openid-configuration`) so an admin
  supplies only the issuer, and DNS-TXT DOMAIN VERIFICATION so a tenant proves it owns
  a routing domain (until then, operator approval gates `allowed_domains`).
- IdP-initiated SSO (the IdP's app-launcher tile), and `amr`/`acr`-based step-up (trust
  the IdP's MFA assertion to skip the app's own).
- Full SCIM: `/Groups` mapped to teams and roles (the committed section-21 mention -
  the skeleton ships Users; Groups is the next layer), `PATCH` partial ops, complex
  filtering, `/ServiceProviderConfig` + `/Schemas` + `/ResourceTypes` discovery, and
  bulk.
- SCIM-triggered ROLE/team assignment from directory group membership (the committed
  "maps directory groups to teams and roles").

## 9. Tests

- **OIDC validation (security-critical)**: a callback with a bad `state` is rejected;
  an id_token with the wrong `iss`, wrong `aud`, bad signature, expired, wrong
  `nonce`, or `email_verified=false` is each rejected; only a fully-valid token
  provisions and mints a session.
- **JIT provisioning**: a first SSO sign-in creates the user + a membership in the SSO
  tenant (not any other); a returning SSO user is matched by (issuer, sub); an
  existing-email user gets the SSO method linked.
- **Domain routing**: an email in a tenant's approved domain routes to that tenant's
  IdP; an unapproved / unclaimed domain does not route (no takeover).
- **SCIM**: a valid SCIM token provisions a member (`POST /Users`); `active=false`
  deactivates the member (access cut); `GET ?filter=userName eq` finds them; a wrong /
  revoked token is 401; tenant A's SCIM token can never touch tenant B (RLS +
  token-scoped tenant).
- **Secret handling**: the `client_secret` and SCIM `token_hash` never appear in the
  data export or the erasure snapshot (the `[Sensitive]` completeness test).
