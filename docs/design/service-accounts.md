# Service accounts and API keys

Status: DESIGN (proposed). The second SaaS grow-into feature
(multi-tenancy.md section 21, the "API keys, service accounts, PATs" bullet).
Docs-first: nothing here is built until this revision is reviewed. It builds on
the generalized RBAC of Part II (multi-tenancy.md sections 13 to 16) and reuses
the bypass hash-lookup pattern that invitation accept established (section 8).
Read those first.

## 1. The decision, up front

- **A service account is a non-human principal that authenticates with a hashed
  API key and carries scoped RBAC grants, not a membership.** A human is a `user`
  principal with a membership row (a system role) plus optional grants; a service
  account is a `service_account` principal with NO membership and NO system role -
  its effective permissions are exactly the grants assigned to it (section 4).
  This is the GCP model (a service account is a first-class principal you grant
  roles to), simplified for the starter: one key per service account, rotatable.
- **The key is a bearer secret, stored only as a hash, shown once.** It mirrors the
  one-time-token pattern already in the repo (SHA-256 hex of a 256-bit random
  secret, base64url), the same "GitHub / Stripe API key" rationale the refresh-
  token helper already cites: a high-entropy secret needs no KDF, and the server
  keeps only the hash. The raw key is returned exactly once, at create and at
  rotate, and never again.
- **A service-account request flows through the identical authorization path as a
  user.** The permission gate reads the caller id from `sub` and asks the RBAC
  resolver for the caller's permissions; it does not care whether the caller is a
  human. The only code that assumes a human is the resolver's active-membership
  gate, which gets one service-account branch (section 4). Everything downstream -
  `RequirePermission`, workspace scoping, RLS - is unchanged.
- **Revocation is immediate, because there is no token.** Unlike a JWT (valid until
  it expires), an API key is re-resolved from its hash on every request, so
  revoking or rotating a key takes effect on the very next call. API keys are more
  responsive to revocation than the access token, not less.
- **PATs and multiple keys per account are documented extensions, not built.** A
  personal access token (a key that acts AS a user, inheriting that user's
  membership) and more than one active key per service account are natural
  follow-ons; section 9 notes where each hangs off this model without a rewrite.

## 2. The credential

The raw key has the shape `sk_<base64url(32 random bytes)>`. The `sk_` prefix is
deliberate: it is what secret scanners (GitHub secret scanning, gitleaks, the
repo's own gitleaks gate) match on, so a leaked key is detectable, and it is also
how the authentication layer tells an API key from a JWT in the `Authorization`
header (section 3). Persisted on the service-account row:

- `key_hash`: `Convert.ToHexStringLower(SHA256(utf8(rawKey)))` - the lookup key,
  the same hashing the invitation and one-time tokens use. Globally unique (the
  lookup is tenant-less), enforced by a unique index.
- `key_prefix`: the first several characters of the raw key (for example
  `sk_ab12cd`), stored in clear for display so an admin can tell keys apart in a
  list without the secret ever being retrievable.

A new `ApiKeySecrets` helper carries `NewKey()` / `Hash(rawKey)` / `Prefix(rawKey)`,
its own copy of the hashing idiom (a module exports no helper types, so the
pattern is duplicated, exactly as `InvitationTokenSecrets` and `OneTimeTokenSecrets`
already are).

## 3. Authentication: a second scheme, added additively

A new `ApiKey` authentication scheme is added ALONGSIDE the JWT bearer scheme,
without changing the JWT path:

- The default authenticate scheme becomes a POLICY (forwarding) scheme with a
  `ForwardDefaultSelector`: if the `Authorization` header value is `Bearer sk_...`
  (or an `X-Api-Key` header is present), it forwards to `ApiKey`; otherwise it
  forwards to `Bearer` (JWT). The forward-CHALLENGE stays `Bearer` always, so an
  unauthenticated request to a protected endpoint still gets the JWT scheme's 401,
  unchanged. No authorization fallback policy is added (the existing design
  deliberately has none, so anonymous surfaces - health, OpenAPI - stay open).
- `ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>`
  reads the key, hashes it with `ApiKeySecrets.Hash`, and calls
  `ITenancyApi.ResolveApiKeyAsync(hash)`. The Api layer cannot touch the bypass
  source (the arch test forbids it), so resolution lives in an allowlisted Tenancy
  control-plane type (section 4) reached through the module's public interface,
  exactly as the impersonation guard reaches its allowlisted reader.
- On a miss (unknown, revoked, or expired key) the handler returns
  `AuthenticateResult.Fail`, which becomes a 401. Every miss collapses to one
  outcome so a holder cannot probe which keys exist.
- On a hit the handler builds a `ClaimsPrincipal` with `sub` = the service-account
  id, `tid` = the resolved tenant, and a new `pt` (principal-type) claim =
  `service_account`. The existing `TenantResolutionMiddleware` (which already runs
  after authentication and reads `tid` from the claim) then binds the request's
  tenant context with no new code.

## 4. Authorization: the resolver's service-account branch

`GetCallerPermissionsAsync` gains an overload that takes the principal type
(the existing user-only methods delegate to it with `PrincipalType.User`, so the
user path is untouched). The permission gate reads the `pt` claim (defaulting to
`user` when absent, so a JWT caller is a user) and passes it through.

In the resolver:

- **User principal**: unchanged - the active-membership gate, the system-role
  permission set, and the union of the user's own and their teams' grants
  (multi-tenancy.md section 13).
- **Service-account principal**: SKIP the membership gate and the system-role step
  (a service account has neither), and resolve permissions ONLY from
  `role_assignments` where `principal_type = 'service_account'` and
  `principal_id` = the caller, at tenant scope and (for a workspace request) the
  requested workspace scope, joined to each role's permissions. No team union (a
  service account is not a team member). Fail-closed: a service account with no
  grants resolves to the empty set and every gate 403s it.

The per-request permission cache key gains the principal type
(`(principalId, workspaceId, principalType)`). Today one request authenticates as
exactly one principal so a collision cannot occur, but folding the type in now
keeps the resolver correct if a future caller resolves more than one principal in
a scope, rather than leaving a silent trap.

This runs on the RLS request path (tid is already bound), so the service account's
grants are read under its own tenant's boundary - it must stay OUT of the bypass
allowlist. Owner-reserved permissions (`tenant:manage`, `tenant:delete`,
`tenant:transfer-ownership`) are never grantable through a custom role, so a
service account can never hold them; a key cannot be minted into tenant takeover.

**Two permissions are additionally not grantable to a service account**:
`roles:manage` and `api-keys:manage`. These are the self-escalation primitives -
`roles:manage` lets a principal author a new custom role from the whole non-owner
-reserved catalogue and assign it to itself, and `api-keys:manage` lets it mint
further keys. A human admin holding them is a supervised, interactive actor; a
service account is a scriptable, always-on, unattended credential, so a single
leaked or over-scoped key holding `roles:manage` would be a silent path to
near-total tenant compromise. `Permissions` names a small `NotServiceAccountGrantable`
set (`roles:manage`, `api-keys:manage`), and `AssignRoleAsync`, when the principal
is a `service_account`, refuses a role whose permission set intersects it (a
distinct problem, `tenancy.permission_not_automatable`). Create-with-initial-role
runs through the same assign path, so it is covered too. A service account can
still hold powerful operational permissions (`members:manage`, `settings:manage`);
what it cannot do is expand its OWN authority without a human.

The `AssignRoleAsync` principal-existence validator gains a `service_account`
branch: a service-account principal is valid when a service-account row with that
id exists in the tenant AND is neither revoked nor past its expiry (mirroring "a
user principal is an ACTIVE member; a team principal is a real team" - a
revoked/expired account can no more receive a new grant than a suspended member).
The stale "only the user principal is supported" class comment on `RoleAssignment`
is corrected to name all three principal types (it already omits the shipped team
type).

## 5. Data model

`tenancy.service_accounts`, tenant-owned, RLS-enforced (the standard
`ITenantOwned` + `enable`/`force row level security` + `tenant_isolation` policy).

| column | type | notes |
|---|---|---|
| `id` | uuid | PK; also the grant `principal_id` |
| `tenant_id` | uuid not null | RLS discriminator |
| `name` | text not null | admin-facing label |
| `key_hash` | text not null | SHA-256 hex of the raw key; globally UNIQUE (lookup) |
| `key_prefix` | text not null | first chars of the raw key, for display |
| `created_by` | uuid not null | the admin (or owner) who created it |
| `created_at` | timestamptz not null | |
| `last_used_at` | timestamptz null | throttled (section 6) |
| `expires_at` | timestamptz null | optional; a key past it fails to resolve |
| `revoked_at` | timestamptz null | set on revoke; a revoked key fails to resolve |

A service account holds permissions through ordinary `role_assignments` rows
(`principal_type = 'service_account'`, `principal_id = service_account.id`), tenant
or workspace scope, so the whole RBAC model (section 13 to 16) applies with no new
grant machinery. The unique `key_hash` index is global (the resolve is tenant-less);
RLS governs visibility, not constraint enforcement, so cross-tenant uniqueness is
fine. A `(tenant_id)` index serves the admin list.

`PrincipalType`/`PrincipalTypes` gain the `service_account` literal in both the
platform and tenancy copies (kept in lockstep, as the doc on those types requires).

## 6. last_used_at without a per-request write

Updating `last_used_at` on every request would add a write to the hot path (and
the repo's auth is deliberately lookup-light). It is instead a THROTTLED,
coalesced write done inside the same bypass resolve, in one statement:
`update tenancy.service_accounts set last_used_at = now() where id = @id and
(last_used_at is null or last_used_at < now() - @throttle)`. With a default
throttle (for example 5 minutes, configurable), a key hammered by a busy client
writes at most once per throttle window, not once per request. `last_used_at` is
therefore approximate by design (accurate to the throttle), which is the right
trade for a "when was this key last active" signal; the exact per-call record is
the audit log, not this column.

## 7. Lifecycle

All endpoints are on the tenant group, gated by a new `api-keys:manage` permission
(added to the catalogue and to `AdminSet`, so admins and owners manage keys; it is
grantable in a custom role like any non-owner-reserved permission).

- **Create** - `POST /api/v1/tenant/service-accounts`: name, plus an optional
  initial role id and scope (tenant, or workspace + workspace id). Creates the
  service-account row and, when a role is given, the matching `role_assignment` in
  the SAME transaction (mirroring scope-aware invitations, so the account lands
  usable). Returns the raw key ONCE in the response body; it is never retrievable
  again. A service account created without a role has no permissions until one is
  assigned (safe by default).
- **List** - `GET /api/v1/tenant/service-accounts`: id, name, key_prefix, created,
  last_used, expires, revoked. NEVER the secret or the hash. Keyset pagination,
  the shared contract.
- **Rotate** - `POST /api/v1/tenant/service-accounts/{id}/rotate`: mint a new
  secret, replace `key_hash` + `key_prefix`, return the new raw key once. The old
  secret stops working immediately (there is one active hash). A grace window where
  the old key keeps working briefly is a documented extension (a second hash column
  with its own expiry).
- **Revoke** - `DELETE /api/v1/tenant/service-accounts/{id}`: set `revoked_at`. The
  key fails to resolve on the next request. Its grants are left in place but inert
  (a revoked key cannot authenticate, so they confer nothing); un-revoke is not
  offered - mint a new account.
- **Expiry**: an optional `expires_at` at create; the resolve treats a past expiry
  as a miss.

Events `tenancy.service_account.created`, `.rotated`, `.revoked` are emitted
(tenant-scoped). They MUST be added to `AuditProjectionConsumer.EventTypes` (the
audit log, increment 8) or the catalogue-completeness test fails the build - which
is the guard working: a new administrative action must be a decision to audit or
to name not-audited, never a silent omission. These are audited.

## 8. Security posture

- The raw key is never logged and never persisted (only its hash and prefix are).
  A key pasted into a log or a chat is compromised; the `sk_` prefix makes the
  gitleaks gate and external scanners catch it.
- The only cross-tenant step is the tenant-less hash lookup on the bypass path,
  which returns just `(tenant_id, service_account_id)` for a live key and one
  generic miss otherwise - the same shape and discipline as invitation accept.
- The rate limiter applies to API-key requests exactly as to any other, so a
  leaked key is still throttled.
- A revoked or rotated key is dead on the next request (no token lifetime to wait
  out), and every key action is in the audit log.
- A service account cannot expand its own authority: the two self-escalation
  permissions (`roles:manage`, `api-keys:manage`) are refused to a service-account
  principal (section 4), so a leaked key is bounded by the grants it was given and
  cannot bootstrap itself to more.

## 9. Placement, deletability, and extensions

The service-account row, its resolver, and the admin endpoints live in
`Starter.Tenancy` (the resolver on the bypass allowlist; the RBAC branch on the
RLS request path); the authentication scheme and handler live in the Api layer
next to the JWT wiring. Deletability: drop the table, the scheme, the endpoints,
the `service_account` principal literal, and the `api-keys:manage` atom, and the
user auth path is untouched.

Extensions, each hanging off this model:
- **PATs (act-as-user tokens)**: a key whose principal is a `user` (not a service
  account), resolving to that user's membership + grants - the resolver's user path
  with an alternate credential. Add a `pat` credential row keyed to a user id.
- **Multiple keys per service account**: split the credential into its own
  `service_account_keys` table (many hashes per account), so rotation can overlap
  and keys can be individually named and revoked.
- **Key scopes narrower than a role**: an OAuth-style scope string on the key
  intersected with the resolved permissions at the gate - additive to section 4.

## 10. Tests (added to the crown-jewel suite)

- **Authenticates and is authorized by its grants**: a service account created with
  a role that has `notes:read` can call a `notes:read` endpoint with its key
  (`Authorization: Bearer sk_...`) and is refused (403) an endpoint needing a
  permission it lacks. One created with no role is 403 everywhere (fail-closed).
- **RLS isolation**: a service account's key resolves only its own tenant; it can
  never read another tenant's data even with a valid key (the tid is bound from the
  key, and RLS scopes every read).
- **Revocation and rotation are immediate**: a revoked key gets 401 on the next
  request; after rotate, the old key is 401 and the new key works - no waiting out a
  token lifetime.
- **Expiry**: a key past `expires_at` is 401.
- **The secret is shown once and stored only hashed**: the create/rotate response
  carries the raw key; the list response never does; the stored `key_hash` is not
  the raw key, and no row holds the raw secret.
- **Owner-reserved cannot be minted**: attempting to create a service account with,
  or assign it, an owner-reserved permission is refused (the catalogue forbids it in
  a custom role, so there is no path to it).
- **The permission gate treats it identically**: the same `RequirePermission`
  endpoint admits a user with the permission and a service account with the
  permission, and refuses both without it.
- **Self-escalation is blocked**: assigning a role containing `roles:manage` or
  `api-keys:manage` to a service account is refused
  (`tenancy.permission_not_automatable`), at both assign and create-with-role;
  the same role assigns fine to a user.
- **last_used_at is throttled**: two rapid authenticated calls advance `last_used_at`
  at most once within the throttle window.
- **Audited**: create, rotate, and revoke each land a row in the tenant audit log
  (increment 8), and the catalogue-completeness test still passes with the three new
  event types categorized.

## 11. Build sequence (this increment)

1. Migration: `tenancy.service_accounts` (RLS policy, the unique `key_hash` index,
   the `tenant_id` list index).
2. `ApiKeySecrets` helper (new key / hash / prefix), the `ServiceAccount` domain
   entity, and the `service_account` literal in `PrincipalType` + `PrincipalTypes`.
3. `ServiceAccountService` (RLS request path): create (optional atomic role grant),
   list, rotate, revoke; emits the three events; extends `AssignRoleAsync`'s
   validator with the `service_account` existence branch (non-revoked, non-expired)
   and the `NotServiceAccountGrantable` refusal; fixes the stale `RoleAssignment`
   class comment to name all three principal types.
4. `ApiKeyResolver` (bypass, allowlisted; added to `TenancyAllowlist`) + the
   `ITenancyApi.ResolveApiKeyAsync(hash)` method, doing the throttled `last_used_at`
   write.
5. `PermissionResolver` service-account branch + the `GetCallerPermissionsAsync`
   principal-type overload (cache key includes principal type); the permission gate
   reads the `pt` claim.
6. `ApiKeyAuthenticationHandler` (Api layer, where `ITenancyApi` is reachable) + a
   named `AddStarterApiKeyAuthentication` extension in the Api layer that registers
   the `ApiKey` scheme and the forwarding policy scheme (default authenticate =
   policy scheme, challenge stays `Bearer`, no fallback policy), called from
   `Program.cs` right after the JWT registration - so the api-key auth wiring lives
   in one named method, not scattered inline.
7. `api-keys:manage` added to `Permissions.All` and `AdminSet`, and the
   `NotServiceAccountGrantable` set defined; the three new event types added to
   `AuditProjectionConsumer.EventTypes`.
8. `ServiceAccountEndpoints` on the tenant group.
9. Tests (section 10) added to the integration suite.
