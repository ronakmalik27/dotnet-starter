# Feature flags

Status: DESIGN (proposed). The fifth SaaS grow-into feature (multi-tenancy.md
section 21). Docs-first: nothing here is built until this revision is reviewed. It
mirrors the billing increment's structure almost exactly (a global operator
catalogue in the platform schema + tenant-scoped rows under RLS + a request-path
resolver), so read billing-and-entitlements.md first; this doc is mostly the
delta and the one inverted default.

## 1. The decision, up front

- **Feature flags are for ROLLOUT and operations, not commerce - and they FAIL
  CLOSED, the opposite of entitlements.** An entitlement answers "does your PLAN
  include this" (commercial, fail-open: unconfigured means allowed). A feature
  flag answers "is this capability turned ON for you right now" (rollout, kill
  switch, gradual release, per-tenant beta). An UNKNOWN or undefined flag resolves
  to OFF: a flag names an in-progress or gated capability, and defaulting an
  unknown flag ON would expose unfinished or killed features. So flags fail closed
  and entitlements fail open, and that contrast is deliberate - the two gate
  different questions and must default in opposite directions. A capability can
  require BOTH (a plan entitlement AND a rolled-out flag); they compose.
- **Three resolution layers, most specific wins.** A flag's value for a caller is:
  a WORKSPACE override if one exists for the active workspace, else a TENANT
  override, else the GLOBAL default (a fixed on/off, or a deterministic percentage
  rollout). This is the standard flag-service shape (LaunchDarkly, Unleash,
  Flagsmith): a global default with progressively narrower overrides.
- **Percentage rollout is deterministic and sticky, never random per call.** A
  10%-rollout flag is ON for the same tenants every time, not a coin flip per
  request (which would flicker a feature on and off mid-session). The bucket is a
  stable hash of `(flagKey, tenantId)` mod 100 compared to the rollout percent, so
  a tenant is stably in or out, and raising the percent only ever adds tenants.
- **Two audiences, two write paths, like billing.** The operator owns the global
  catalogue (define a flag, its default, its rollout, and whether tenants may
  override it); a tenant admin owns its own tenant/workspace overrides, but only
  for flags the operator marked tenant-overridable. A tenant can never flip a flag
  the operator holds centrally (a kill switch or a not-yet-GA feature).
- **Placement mirrors billing**: the global catalogue is `platform.feature_flags`
  (no RLS, operator-managed, request role REVOKEd write); the overrides are
  `platform.feature_flag_overrides` (tenant-owned, RLS), both in `PlatformDbContext`;
  a Platform evaluator reads both on the request path.

## 2. Data model

`platform.feature_flags`, global, NO RLS (operator catalogue):

| column | type | notes |
|---|---|---|
| `key` | text | PK; the flag identifier code checks against |
| `description` | text not null | what the flag controls |
| `default_enabled` | boolean not null | the global default when no rollout and no override |
| `rollout_percentage` | int null | 0..100; when set, overrides `default_enabled` via the deterministic bucket; NULL = use `default_enabled` |
| `tenant_overridable` | boolean not null | may a tenant admin set an override for this flag |
| `archived_at` | timestamptz null | an archived flag resolves OFF and is hidden from the tenant surface |
| `created_at` / `updated_at` | timestamptz not null | |

`platform.feature_flag_overrides`, tenant-owned, RLS (`ITenantOwned` + FORCE RLS +
the standard `tenant_isolation` policy):

| column | type | notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid not null | RLS discriminator |
| `flag_key` | text not null | the flag this overrides |
| `scope_type` | text not null | `tenant` or `workspace` |
| `scope_id` | uuid null | the workspace id for a workspace override; NULL for tenant scope |
| `enabled` | boolean not null | the override value |
| `set_by` / `updated_at` | uuid / timestamptz not null | |

Unique `(tenant_id, flag_key, scope_type, scope_id)` with `NULLS NOT DISTINCT`
(so a tenant-scope override, `scope_id` NULL, is unique per flag). `NULLS NOT
DISTINCT` is the idiom the `roles` catalogue index (`ix_roles_tenant_id_workspace
_id_key`) uses for its nullable `workspace_id`, NOT the `role_assignments` shape
(which splits into two partial unique indexes). It is the deliberate choice here:
`scope_type` is part of the key, so a NULL `scope_id` only collides within
`scope_type = 'tenant'` rows (exactly "one tenant override per flag"), and a
single index with `NULLS NOT DISTINCT` is what lets a PUT-as-upsert
(`ON CONFLICT (...) DO UPDATE`) work when `scope_id` is NULL. The catalogue is seeded EMPTY (a flag is a
deliberate operator act; there is nothing to gate until one is defined), and the
request role is REVOKEd write on `platform.feature_flags` (operator-managed, like
`platform.plans`). The overrides table is normal request-role DML (a tenant admin
writes its own, RLS-scoped).

## 3. The evaluator

`IFeatureFlagEvaluator` (a Platform service, request path): `IsEnabledAsync(flagKey,
workspaceId?)` resolves in order:

1. The flag's catalogue row. If the flag is unknown or archived, return OFF
   (fail closed).
2. If `workspaceId` is given and a `workspace`-scope override for `(flagKey,
   workspaceId)` exists in this tenant (RLS-scoped), return its `enabled`.
3. Else if a `tenant`-scope override for `flagKey` exists, return its `enabled`.
4. Else the global default: if `rollout_percentage` is set, return `bucket(flagKey,
   tenantId) < rollout_percentage`; else `default_enabled`.

It reads `platform.feature_flags` (no RLS) and `platform.feature_flag_overrides`
(RLS) through the request-scoped `PlatformDbContext` in one read transaction (so
the tenant GUC is set for the override read) - never the bypass source, exactly
like the entitlement source. Resolution is per-request cached on `(flagKey,
workspaceId)` (a request rarely evaluates the same flag twice, but a loop might).

**The rollout bucket must use a fixed, cross-process-stable hash - NEVER
`string.GetHashCode()` or `HashCode.Combine`.** Both are randomized per process by
.NET (a deliberate hash-flooding mitigation), so they give a different bucket on
every replica and every restart - the same tenant would flicker in and out of a
rollout, and a same-process unit test would never catch it (the seed is stable
within one process). The bucket is FNV-1a computed in application code over the
UTF8 bytes of `flagKey + ":" + tenantId`, accumulated as an UNSIGNED integer
(`uint`), then `% 100` - unsigned throughout, so there is no `Math.Abs` (and no
`Math.Abs(int.MinValue)` overflow: that call throws in .NET). A tenant is ON when
`bucket < rollout_percentage`; because the hash is fixed, a tenant is stably in or
out and raising the percent only adds tenants. A golden-value unit test pins
`Bucket("known-flag", knownTenantGuid)` to a hardcoded literal, which fails
immediately (in any single process) if someone reaches for `GetHashCode`.

For code that checks many flags at once (a client bootstrap that hydrates the UI),
a batch `EvaluateAllAsync(workspaceId?)` returns the resolved map in one pass over
the catalogue + overrides.

## 4. Gating

Two ways to gate, because flags are checked in more places than a plan feature:

- **In code**: inject `IFeatureFlagEvaluator` and branch on `IsEnabledAsync`. This
  is the common case (a flag guards a code path, not a whole endpoint).
- **At an endpoint**: `RequireFeatureFlag(flagKey)` filter, which returns 404 (NOT
  403/402) when the flag is off - a not-yet-released feature should look like it
  does not exist, not like it is forbidden or paywalled, so a probe cannot map the
  unreleased surface. Composes after `RequireTenant`.

A flag gate and an entitlement gate are independent and both may apply: a feature
can be gated by `RequireEntitlement("x")` (your plan includes it) AND
`RequireFeatureFlag("x-rollout")` (it is turned on for you). Order: the flag (404,
hide) composes OUTERMOST when hiding matters more than the paywall message; the
default worked examples keep them on separate concerns so no single route needs
both.

## 5. Admin surfaces

- **Super-admin (global catalogue)**, on the platform group behind
  `RequirePlatformAdmin`, cross-tenant on the bypass path (the plan-CRUD pattern):
  `GET/POST /api/v1/platform/feature-flags`, `PATCH
  /api/v1/platform/feature-flags/{key}` (default, rollout, tenant_overridable,
  archive). Catalogue edits are audited synchronously on the platform log via
  `IPlatformAuditWriter` (like plan edits).
- **Tenant admin (own overrides)**, on the tenant group, gated by a new
  `feature-flags:manage` permission (in `AdminSet`): `GET
  /api/v1/tenant/feature-flags` (the resolved flags plus which are overridable),
  `PUT /api/v1/tenant/feature-flags/{key}` (set a tenant or workspace override),
  `DELETE /api/v1/tenant/feature-flags/{key}` (clear the override, falling back to
  the layer below). A `PUT`/`DELETE` for a flag the operator did NOT mark
  `tenant_overridable` is refused (`tenancy.flag_not_overridable`, 403) - a tenant
  cannot touch an operator-held flag. Override changes emit a tenant-scoped
  `tenancy.feature_flag.override_set` / `.override_cleared` event (audited and
  webhook-deliverable).

## 6. Feature flags vs. entitlements (why both exist)

They look similar (a per-tenant boolean) but answer different questions and default
opposite ways, so keeping them separate is correct, not redundant:

- Entitlement = commercial ("your plan includes it"), fails OPEN, changes with the
  billing plan, operator-and-tenant-visible as a tier capability.
- Feature flag = operational ("it is turned on for you"), fails CLOSED, changes on
  a release/rollout/kill-switch timeline independent of price, and is a deploy-time
  concern.

A GA feature that a paid tier unlocks is an entitlement; a feature being rolled out
to 10% of tenants, or dark-launched, or kill-switchable in an incident, is a flag.
A single capability can sit behind both. Folding them into one table would force
one default direction on two problems that need opposite ones.

## 7. Placement and deletability

Catalogue, overrides, evaluator, and the filter live in Platform / the Api layer;
the tenant-admin override endpoints call the Platform override service (request
path, RLS). Deletability: drop the two tables, the evaluator, the filter, the two
permissions/problems, and the code drops back to un-flagged (every `IsEnabledAsync`
call site either removes the flag or hard-codes the value). No event-spine change.

## 8. Grow-into (documented, not built)

Multivariate flags (string/number variants, not just boolean), targeting rules
(enable for tenants matching an attribute, the ABAC-adjacent case), scheduled
rollouts, and an SDK-streaming evaluation endpoint for a client to subscribe to
flag changes - all layer onto the catalogue + override tables without a rewrite,
and are where a team graduates to a hosted flag service (LaunchDarkly/Unleash) if
the need outgrows the built-in evaluator. The built-in one is the correct starter
bar; the seam is `IFeatureFlagEvaluator` (swap the implementation for a provider
SDK, keep the call sites).

## 9. Tests (added to the crown-jewel suite)

- **Fail closed**: an unknown or archived flag resolves OFF; `RequireFeatureFlag`
  for it returns 404.
- **Resolution precedence**: a workspace override beats a tenant override beats the
  global default; clearing the workspace override falls back to the tenant
  override, then to the global default.
- **Deterministic rollout**: a flag at 50% rollout resolves the SAME value for a
  given tenant across repeated calls; a tenant in the bucket stays in, and raising
  the percent never flips an in-tenant out. (Test with two tenant ids that land on
  opposite sides of a chosen percent.) PLUS a GOLDEN-VALUE unit test that pins
  `Bucket("known-flag", knownTenantGuid)` to a hardcoded expected literal - this
  fails on the first run, in any single process, if the implementation uses
  `string.GetHashCode` / `HashCode.Combine` (whose per-process seed a same-process
  repeat-call test cannot catch).
- **RLS isolation**: a tenant sees and sets only its own overrides; tenant A's
  override never affects tenant B's resolution.
- **Overridable gate**: a tenant admin can override a `tenant_overridable` flag but
  is refused (`flag_not_overridable`) on one the operator holds centrally.
- **Super-admin only**: catalogue CRUD requires `RequirePlatformAdmin`; a tenant
  admin is 403; `feature-flags:manage` gates the tenant override surface (a member
  is 403).
- **Entitlement and flag are independent**: a route gated by both admits only when
  the plan includes it AND the flag is on; failing either blocks, with the flag's
  404 hiding taking precedence when both are composed.
- **Audited**: a catalogue edit lands a platform-audit row; an override set/clear
  lands a tenant audit row (and is webhook-deliverable), catalogue-completeness
  green with the new event types.

## 10. Build sequence (this increment)

1. Migration: `platform.feature_flags` (no RLS) + `platform.feature_flag_overrides`
   (RLS, the unique index with NULLS NOT DISTINCT). Catalogue seeded empty. The
   request-role write REVOKE on `platform.feature_flags` is added to the boot-time
   `TenantRoleProvisioner` grant pass (after the blanket grant, like `plans` /
   `audit_log`), NOT the EF migration DDL.
2. `FeatureFlagRow` / `FeatureFlagOverrideRow` mapped in `PlatformDbContext`
   (override is `ITenantOwned` with the tenant filter; catalogue is not).
3. `IFeatureFlagEvaluator` (Platform, request path): `IsEnabledAsync` +
   `EvaluateAllAsync`, the fail-closed precedence, the deterministic bucket, the
   per-request cache.
4. `RequireFeatureFlag(flagKey)` filter (404 when off) + the in-code evaluator DI.
5. Super-admin catalogue CRUD (bypass, audited via `IPlatformAuditWriter`) + the
   tenant-admin override service (request path, RLS) with the `tenant_overridable`
   gate; `feature-flags:manage` in `Permissions.All` + `AdminSet`; the two
   override events in `DeliverableEvents`.
6. Endpoints: platform `/api/v1/platform/feature-flags`; tenant
   `/api/v1/tenant/feature-flags`.
7. Tests (section 9) in the integration suite.
