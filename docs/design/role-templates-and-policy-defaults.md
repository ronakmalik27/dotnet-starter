# Global role templates and platform policy defaults

Status: DESIGN (proposed). The ninth SaaS grow-into feature (multi-tenancy.md
section 21). Docs-first: nothing here is built until this revision is reviewed. Two
independent operator-plane features the section-21 bullet groups together: (A)
global ROLE TEMPLATES the super-admin seeds into every tenant, and (B) platform
POLICY DEFAULTS (password, session, lockout) the whole install inherits.

## 1. The decision, up front

- **Both are operator-owned platform catalogues; tenants consume, they do not
  author.** Role templates and policy defaults live in the `platform` schema, no
  RLS, super-admin CRUD (the plans / feature-flag catalogue shape). A tenant never
  edits a template or a platform default; it receives a COPY (a role template
  becomes one of the tenant's own custom roles) or INHERITS a floor (a policy
  default the tenant may tighten but not loosen).
- **A role template is a SEED, not a live link.** Seeding a template into a tenant
  creates an ordinary `tenancy.roles` custom role owned by that tenant (section 2).
  After seeding the copy is the tenant's - it may rename, re-permission, or delete
  it, and editing the template later does NOT retro-change already-seeded copies.
  This is the standard "scaffold a sensible starting role" behavior (GitHub's
  default org roles, Auth0's role templates), not a permanent binding.
- **The global-user model bounds where "a tenant may tighten" is even coherent, and
  the design says so honestly.** The section-21 bullet promises a tenant "inherits
  and may tighten" password, session, and lockout policy. That phrasing assumes
  tenant-scoped users. In THIS starter a user is GLOBAL (multi-tenancy.md section 1):
  registration and login happen with no tenant context, before any tenant is
  selected. So PASSWORD policy (enforced at global register/change) and LOCKOUT
  policy (enforced at global login) are install-wide by nature - a user in three
  tenants has one password and one login, so "tenant A's stricter password rule"
  has no coherent enforcement point. SESSION policy is different: the tenant access
  token (`tid`) is minted per tenant (multi-tenancy.md section 5), so a tenant CAN
  tighten its own session lifetime. Therefore: platform defaults for all three are
  operator-set and enforced install-wide; tenant TIGHTENING is built for SESSION
  (where it is coherent) and DOCUMENTED as a tenant-scoped-users grow-into for
  password and lockout (section 7). Pretending otherwise would ship a knob that
  silently does nothing.
- **Tighten means tighten, enforced, never loosen.** A tenant session override must
  be validated to be no LONGER than the platform default (a shorter token lifetime
  is tighter/safer); an attempt to set a longer lifetime than the platform floor is
  rejected. The effective session lifetime is `min(platform default, tenant
  override)`.

## 2. Role templates

`platform.role_templates`, global, NO RLS (operator catalogue, super-admin CRUD, the
plans shape):

| column | type | notes |
|---|---|---|
| `key` | text | PK; the stable template identifier |
| `name` | text not null | the role name seeded into the tenant |
| `description` | text not null | |
| `permissions` | text[] not null | permission atoms from the closed catalogue (validated against `Permissions.All` on write) |
| `assignable_scopes` | text[] not null | `tenant` and/or `workspace` (the custom-role scope vocabulary, section 13) |
| `created_at` / `updated_at` | timestamptz not null | |

- Super-admin CRUD on the platform plane (`RequirePlatformAdmin`), audited
  synchronously on the platform audit log (`platform.role_template.created` /
  `.updated` / `.deleted`, the plan-CRUD pattern; in the `AuditLogTests` NotAudited
  set). Write-time validation: every permission is a real catalogue atom, and none
  is an owner-reserved permission (`Permissions.OwnerReserved` can never be templated
  into a tenant custom role, the same structural block custom roles already carry).
- **Seeding at provisioning.** `TenantProvisioner` (bypass), after it creates the
  owner membership and INSIDE the same provisioning transaction (atomic with the
  user+tenant+membership commit - seeding is a cheap local write with no external
  I/O, so it belongs in the commit, not the best-effort post-commit path the
  verification email uses), seeds one `tenancy.roles` custom role per active template
  plus its `tenancy.role_permissions`, for the new tenant. A seeded role carries a
  `template_key` column (nullable) so a re-seed is idempotent (skip a template
  already seeded for the tenant) and so "which roles came from a template" is
  answerable; a tenant-authored custom role has `template_key` null.
- **Do NOT call `CustomRoleService.CreateRoleAsync` to seed.** That method opens its
  OWN transaction unconditionally (no join-or-begin guard), so calling it inside the
  provisioner's already-open transaction throws (EF Core forbids a second
  transaction on a context that already has one). Factor the permission-filtering and
  role+role_permissions insert into an internal, TRANSACTION-AGNOSTIC helper (it
  writes on whatever transaction is already open, the way the seeding path and the
  endpoint path can both call it), and have the endpoint-facing `CreateRoleAsync`
  wrap that helper in its own transaction while the provisioner calls the helper
  directly inside its open one. (Alternatively add a `CurrentTransaction is null`
  join-or-begin guard like `SessionIssuer` - but the shared helper is cleaner.)
- **A partial unique index `(tenant_id, template_key) WHERE template_key IS NOT NULL`**
  is the race backstop for idempotency (mirroring the custom-role key's app-check +
  DB-unique-index pattern): a concurrent bulk-seed and a concurrent new-tenant
  provision cannot double-seed the same template, and the app-level "skip if already
  seeded" pre-check is the friendly path.
- **Plan permissions are respected, not bypassed.** A template permission the
  tenant's plan does not grant (billing-and-entitlements.md section 4a) is SKIPPED
  when seeding (the seeded role gets the plan-allowed subset), never seeded in
  violation of the plan - a template is a convenience, not a permission-escalation
  path. Fail-open on an unrestricted plan (the default) seeds the full template. If
  skipping leaves the role empty, the role is still created (an empty custom role is
  valid and the operator can widen the plan later).
- **Applying to existing tenants.** A super-admin action
  `POST /api/v1/platform/role-templates/{key}/seed` seeds one template into all
  tenants (or a named tenant), idempotently (the `template_key` guard). Existing
  tenants provisioned before a template existed get it this way. Bypass path,
  per-tenant `WITH CHECK`-safe writes.
- The tenant sees seeded roles as ordinary custom roles through the existing
  custom-role API (list/edit/delete/assign) - no new tenant-facing surface. Deleting
  a seeded role is allowed (it is the tenant's copy).

## 3. Platform policy defaults

`platform.policy_defaults`, global, NO RLS, a SINGLE row (a `bool one_row` primary
key fixed to true with a `check (one_row)` so there is exactly one). This is a
FIRST-OF-ITS-KIND shape here (the other operator catalogues - plans, feature_flags -
are multi-row with an `is_default` partial index); the singleton is simpler for a
true install-wide record - no demote-race, no "which is active" - but call it out so
the next reader is not surprised it diverges from the plans pattern. Super-admin
reads and updates it; audited (`platform.policy.updated`).

| field (jsonb or columns) | default | enforced at |
|---|---|---|
| `password_min_length` | 10 (today's `PasswordPolicy.MinimumLength`) | register / set / change password |
| `access_token_lifetime_seconds` | 900 (today's 15 min) | access-token issue |
| `refresh_lifetime_seconds` | 2592000 (today's 30 days) | refresh-family issue |
| `lockout_max_attempts` | 10 | login |
| `lockout_duration_seconds` | 900 (15 min) | login |

- Seeded once by the migration with today's values, so nothing changes behavior on
  ship (the reproducibility discipline: the defaults ARE the current constants).
- A request-scoped `IPolicyDefaults` reader (Platform) exposes the current values
  (read no-RLS like the plan catalogue; a short in-process TTL cache is worthwhile
  since the lockout fields are read on the login hot path - the one path the auth
  code already flags as brute-force-exposed - and per-request caching does not help
  across concurrent attack traffic). If the singleton row is ever ABSENT (a DB that
  has not run the seed), the reader FAILS CLOSED to the built-in constant defaults
  (the same explicit-fallback discipline `TenantProvisioner.ReadDefaultPlanAsync`
  uses), never throwing on the auth path.
- **`PasswordPolicy` reads `password_min_length`** from the reader instead of the
  `const` (only the first branch; the `MaximumLength` Argon2 CPU-guard is untouched).
- **The token lifetimes: switch the MINT, keep the impersonation cap on the const.**
  `StarterAuth.AccessTokenLifetime` / `RefreshFamilyLifetime` have five readers - do
  NOT blanket find/replace them. `AccessTokenIssuer.Issue` (the actual mint) reads
  `IPolicyDefaults` AND RETURNS the resolved lifetime, so the three `expires_in`
  -reporting call sites (`SessionIssuer`, `SelectTenantHandler`, `RefreshHandler`)
  report the SAME number the token actually carries instead of independently
  re-reading the const (a stale `expiresIn` that disagrees with `exp` is the bug).
  The fifth reader, `PlatformAdminService.StartImpersonationAsync`'s grant cap, MUST
  keep reading the literal `StarterAuth.AccessTokenLifetime` const - the impersonation
  window is a hard security ceiling that policy must never widen. Call this exception
  out in the code.
- Options-validation bounds each field (positive, sane maxima) on write.

## 4. Password and lockout (install-wide)

- **Password**: `PasswordPolicy.Check` reads `password_min_length` from
  `IPolicyDefaults`. The breach check and the `MaximumLength` CPU-guard are
  unchanged. Raising the platform minimum applies to the next register / change; it
  does not invalidate existing passwords (no forced rotation - the NIST position the
  policy already documents).
- **Lockout (new)**: brute-force protection at login, keyed on the password
  credential (the global user's `auth_methods` password row gains `failed_attempts
  int not null default 0` and `locked_until timestamptz null`).
  - On a login attempt where `locked_until` is set and `> Clock.UtcNow`: reject with
    the same generic invalid-credentials answer (NOT a distinct "locked" message that
    would confirm the account exists / is under attack) - a `423`-style lock is a
    documented option (section 7) but the enumeration-safe default is the generic 401.
    **The locked branch MUST still pay the Argon2 cost before returning** (call
    `PasswordHasher.VerifyDummy(password)` or verify-and-discard, exactly like the
    "no usable credential" branch): a locked account that early-returns before
    hashing is measurably FASTER than an unknown account or a non-locked wrong
    password (which both pay full Argon2), and that timing delta is a real oracle
    revealing "this email exists and is currently locked". Do not skip the hash on
    the locked path even though skipping it is the whole CPU-saving appeal of a
    lockout - the timing equalization outranks the CPU saving here.
  - On a wrong password: increment `failed_attempts` and conditionally set
    `locked_until` in ONE standalone `ExecuteUpdateAsync` (NO ambient transaction -
    `LoginHandler` deliberately holds no transaction at the wrong-password point, to
    avoid pinning a pooled connection during Argon2 under brute-force load; a
    read-modify-write via the tracked entity would race and undercount). Express the
    threshold in the update itself: set `failed_attempts = failed_attempts + 1`, and
    `locked_until = case when failed_attempts + 1 >= @max then @now + @duration else
    locked_until end`, so concurrent attempts serialize on the row and cannot lose an
    increment.
  - On a successful password verify: reset `failed_attempts = 0`, `locked_until =
    null` (a single `ExecuteUpdateAsync`).
  - Auto-unlock is implicit: once `locked_until <= now` a fresh attempt is allowed
    (and a wrong one starts the count again). No unlock job needed.
  - Google-OIDC sign-in is unaffected (no password credential, no lockout).
  - **Accepted DoS tradeoff, named because the user model makes it bigger.** An
    attacker who knows a victim's email can lock them out by spamming wrong passwords
    - the standard lockout tradeoff. But because the user is GLOBAL, one lockout locks
    the victim out of EVERY tenant they belong to at once, not one - a materially
    larger blast radius than a per-tenant SaaS lockout. This is accepted and
    documented (not a defect); the mitigations (a `423` with a retry-after, or IP /
    progressive lockout that does not lock the account on distributed attempts) are
    section-7 grow-into.

## 5. Session tightening (the one coherent tenant override)

- `tenancy.tenants` gains a nullable `session_max_seconds` (a tenant-set tid-token
  lifetime override). A tenant admin sets it on the existing settings-update path,
  gated by `RequirePermission(settings:manage)` - the permission that route actually
  carries (NOT `tenant:manage`, which is owner-reserved and never grantable to a
  custom role; the settings path is admin-reachable via `settings:manage`). It is
  validated `<= platform access_token_lifetime_seconds` (tighter only); a longer
  value is rejected (`tenancy.session_longer_than_platform`).
- **The cross-module seam (arch-test-critical).** The tid mint lives in
  `Starter.Identity` (`SelectTenantHandler`, `RefreshHandler`), which the module
  -boundary arch test forbids from referencing any `Starter.Tenancy` type or table.
  So the override is read through a `Starter.Platform`-declared port
  `ITenantSessionPolicyReader` (mirroring the existing `ITenantRoleReader` /
  `IPermissionResolver` ports Tenancy implements and Identity consumes via DI against
  the port, never against Tenancy). The issuer resolves the effective lifetime as
  `min(platform default, tenant override)`.
- **Select-tenant vs refresh - resolve on BOTH, per the review.** `SelectTenantAsync`
  is endpoint-mediated (only the composition layer calls it), so the endpoint can
  resolve the override and pass a resolved lifetime in. `RefreshAsync` is a
  pure-Identity endpoint with no Tenancy touchpoint today; it must consult the port
  too (via DI) when the refresh carries a `tid`, so a tenant that TIGHTENS its
  session after a token was issued sees the shorter lifetime on the very next
  refresh - re-resolve the CURRENT override per rotation, never a value captured
  stale at select-tenant time. (Documented tradeoff: this adds one port read to the
  refresh path when a tid is present; that is the cost of the override being live.)
- Only the tenant access token is affected. The refresh family lifetime and the
  no-tenant access token stay install-wide (they are not scoped to one tenant).
- This is the worked example of "inherit and may tighten" on the dimension where the
  global-user model makes it coherent. Password and lockout tightening follow the
  same effective-is-tighter shape once users are tenant-scoped (section 7).

## 6. Events and audit

- Role-template CRUD and policy-default updates are operator actions, audited
  synchronously on the platform audit log through `IPlatformAuditWriter` (the plan /
  impersonation pattern), added to the `AuditLogTests` NotAudited set.
- Seeding a template into a tenant creates ordinary custom-role rows; the existing
  `tenancy.role.created` / `tenancy.role_assignment.*` events already cover the
  tenant-scoped side (no new tenant event).
- A tenant setting its session override rides the existing
  `tenancy.tenant.settings_updated` event (no new event).

## 7. Deferred (documented grow-into, not built)

- **Tenant tightening of PASSWORD and LOCKOUT policy.** Coherent only once users are
  tenant-scoped (or credentials are per-tenant): in a global-user model there is one
  password and one login per user across all their tenants, so a per-tenant password
  or lockout floor has no single enforcement point. The effective-is-tighter shape
  (section 1) transfers unchanged the day the user model does; until then only
  session tightening is built.
- A distinct `423 Locked` response (instead of the enumeration-safe generic 401) for
  a first-party UI that wants to show "account locked, try again in N minutes".
- Live re-seeding / drift report (which tenants diverged from a template since
  seeding), and a "template updated, re-apply to all" bulk action beyond the
  idempotent seed.
- Per-tenant password composition / rotation rules, and IP-based / progressive
  lockout (exponential backoff), beyond the fixed count-and-duration lockout here.

## 8. Deletability

Additive and mostly removable: drop `platform.role_templates` + its CRUD + the
provisioner seeding + the `template_key` column; drop `platform.policy_defaults` +
`IPolicyDefaults` and revert `PasswordPolicy` / the token issuers to the constants
(which are exactly the seeded defaults); drop the `auth_methods.failed_attempts` /
`locked_until` columns and the login lockout branch; drop `tenancy.tenants.session_max_seconds`
and the tightened-lifetime resolution. The system roles, the custom-role engine, and
the base auth flows are untouched.

## 9. Tests

- **Role templates**: super-admin CRUD (permission-atom validation, owner-reserved
  rejected); provisioning seeds active templates as tenant custom roles (plan-allowed
  subset only; unrestricted plan seeds the full set); re-seed is idempotent
  (`template_key` guard); a tenant can edit/delete a seeded role; non-super-admin is
  refused.
- **Policy defaults**: updating `password_min_length` changes what a new password
  must satisfy (a 10-char password rejected after the floor is raised to 12);
  updating the access-token lifetime changes the issued token's expiry.
- **Lockout**: N wrong passwords lock the credential (further attempts fail even with
  the RIGHT password while locked); the lock is the generic 401 (enumeration-safe);
  a correct password after `locked_until` elapses (pin the clock) succeeds and resets
  the counter; a successful login resets the counter; Google sign-in is unaffected.
- **Session tightening**: a tenant override `<= platform` is accepted and shortens
  the tid token; an override `> platform` is rejected; a tenant with no override
  inherits the platform lifetime.
