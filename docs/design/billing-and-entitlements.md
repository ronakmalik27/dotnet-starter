# Billing, plans, and entitlements

Status: DESIGN (proposed). The fourth SaaS grow-into feature (multi-tenancy.md
section 21, the "Billing ... and entitlements" bullet). Docs-first: nothing here
is built until this revision is reviewed. It uses the `plan` and `seat_limit`
fields already on the tenant, the super-admin plane (multi-tenancy.md section 7),
and the audit log (audit-log.md). Read those first.

## 1. The decision, up front

- **A plan is an operator-owned catalogue entry; a tenant is assigned one; a plan
  carries entitlements (a feature set and limits).** The SaaS operator defines the
  plans (free, pro, enterprise, ..); each tenant's `plan` names one; the plan's
  entitlements answer "may this tenant use feature X" and "what is this tenant's
  limit for Y". This is the standard SaaS shape (Stripe Billing, every B2B tier
  page): the price tier maps to a capability set, and the app gates on the
  capability, not the price.
- **The starter builds the ENTITLEMENT MODEL, not a payment processor.** Charging a
  card, subscriptions, proration, invoices, and dunning are a payment provider's
  job (Stripe, Paddle, Chargebee). The reusable, stack-defining piece is the
  plan/entitlement model and its enforcement; the provider is a plug-in that, on a
  successful checkout or a subscription change, calls the same assign-plan path a
  super-admin uses (section 7). That provider callback is an INBOUND webhook (not
  to be confused with the outbound webhooks of webhooks.md); wiring one is a
  documented seam (section 9), the same posture SSO/SCIM take.
- **Entitlement checks FAIL OPEN, unlike every security gate.** Permissions and RLS
  fail closed (no proof, no access). Entitlements are the opposite: they are a
  COMMERCIAL gate, so when billing is not configured - no plan on the tenant, an
  unknown plan key, or a plan that declares no feature restriction - every feature
  is available. Failing closed would lock every tenant out of every feature the
  moment the filter ships and before any plan is defined. So the filter is a no-op
  until an operator deliberately defines a plan that restricts a feature; only then
  does it bite. This is a deliberate, documented inversion of the fail-closed rule,
  correct precisely because a missing commercial entitlement must never deny a
  paying-by-default starter its own features.
- **Plans live in the platform schema, operator-managed, read on both paths.** The
  catalogue is global (no `tenant_id`), like the permission catalogue and the
  platform-admin roster, so `platform.plans` is a no-RLS table in
  `PlatformDbContext` (the `platform_admins` shape). The request path resolves a
  tenant's entitlements from it; the super-admin path edits it. Writes are revoked
  from the request role (operator-managed, like the audit log), so a tenant can
  never edit the catalogue.

## 2. Data model

`platform.plans`, global, NO RLS (operator catalogue):

| column | type | notes |
|---|---|---|
| `key` | text | PK; the value stored in `tenant.plan` (e.g. `free`, `pro`) |
| `name` | text not null | display name |
| `features` | text[] null | the feature keys this plan INCLUDES; NULL = unrestricted (all features) |
| `permissions` | text[] null | the RBAC permission atoms a custom role on this plan may hold; NULL = unrestricted (section 4a) |
| `limits` | jsonb not null | numeric limits, e.g. `{ "seatLimit": 5, "maxWorkspaces": 3 }` |
| `is_default` | boolean not null | the plan a new tenant gets; exactly one true (a partial unique index enforces it) |
| `created_at` / `updated_at` | timestamptz not null | |

The migration seeds one row: `free`, `features = NULL` and `permissions = NULL`
(both unrestricted), `limits = { seatLimit: 5 }`, `is_default = true`. The seed
MUST write `features` and `permissions` as SQL NULL, not an empty array `{}` - by
the semantics below they are opposites, and a mistaken `{}` would strip every
feature and every grantable permission from every tenant at once. So a
freshly-provisioned tenant resolves to "all features, all permissions, 5 seats"
and nothing that ships today changes behavior. Operators add `pro` / `enterprise`
(and any restrictive lists) through the super-admin API.

`features` / `permissions` semantics: NULL means the plan restricts NOTHING. A
non-null array means the plan is CLOSED to exactly that set - anything not listed
is denied. This is what lets the default plan be unrestricted (NULL) while a
paid-tier-gating operator sets explicit lists.

Exactly one `is_default = true` is a real invariant, enforced by a partial unique
index (not just app discipline, which a concurrent double-promote could violate):
`create unique index ux_plans_is_default on platform.plans (is_default) where
is_default`. A `PATCH` that promotes a new default demotes the current one and
promotes the target in one transaction; the index makes a torn state impossible.

`is_default` DRIVES provisioning: `TenantProvisioner` reads the `is_default`
plan's key and its `seatLimit` at signup instead of a hardcoded literal (falling
back to `free` / 5 only if no default row exists), so changing the default plan
actually changes what new tenants get.

Boot-time grant hardening (like the audit log): after the blanket schema grant,
`revoke insert, update, delete on platform.plans from starter_app`, so the
request role may only READ the catalogue; only the bypass role (super-admin path)
edits it.

The tenant's `plan` (already a nullable text column) is the assignment. Assigning
a plan also denormalizes the plan's `seatLimit` onto the tenant's `seat_limit`
column, so the existing race-proof seat check in invitation-accept
(multi-tenancy.md section 8) stays exactly as it is - it keeps reading
`seat_limit` off the locked tenant row, now kept in sync with the plan. (`Plan`
and `SeatLimit` become settable on the entity, matching `Status`.)

## 3. Resolving entitlements

- **`Entitlements`** is a resolved value object: `Features` and `GrantablePermissions`
  (each a set, or "unrestricted" when the plan's list is null) and `Limits`
  (key -> int). `HasFeature(key)` / `AllowsPermission(key)` are true when
  unrestricted OR the set contains the key; `GetLimit(key, fallback)` returns the
  plan's limit or a fallback.
- **`IEntitlementSource`** (a Platform service) loads the `platform.plans`
  catalogue and resolves a plan key to `Entitlements`. An unknown or null key
  resolves to UNRESTRICTED (fail open, section 1). It reads `platform.plans`
  through the request-scoped `PlatformDbContext` (a no-RLS table needs no bypass).
  The catalogue is tiny and read per resolve, so there is no stale-after-edit
  window (a tightened plan takes effect on the next request); a short-TTL cache is
  an optional refinement, not needed for correctness.
- **`ITenancyApi.GetCallerEntitlementsAsync`** is the request-path entry point: it
  reads the ACTIVE tenant's `plan` under RLS (the `GetSeatsAsync` pattern - an
  explicit read transaction so the tenant GUC is set), then resolves it via
  `IEntitlementSource`. Tenancy may call the Platform service (modules depend on
  Platform). One call gives a caller its full entitlement picture.

## 4. Gating a feature

`RequireEntitlement(feature)` is an endpoint filter modelled exactly on
`RequirePermission`: it resolves `ITenancyApi.GetCallerEntitlementsAsync`, and if
`!HasFeature(feature)` short-circuits with a new `402 starter:payment-required`
problem ("your plan does not include this feature"); otherwise it calls the next
filter. It composes AFTER `RequireTenant` (a no-tenant request answers
400 tenant-required first) and is orthogonal to `RequirePermission` (a caller
needs BOTH the permission AND the entitlement; the two express different things -
"are you allowed" vs "does your plan include it"). On a route carrying both,
`RequirePermission` composes BEFORE `RequireEntitlement`, so a caller who is not
even authorized for the feature gets a 403 and never learns whether the plan
would have gated it (a 402 leaks that the feature exists behind a paywall).

The worked example gates the webhook endpoints with
`RequireEntitlement("webhooks")` (webhooks is a canonical paid-tier feature). This
changes nothing for existing tenants: they are on the seeded `free` plan whose
`features` is NULL (unrestricted), so `HasFeature("webhooks")` is true and every
existing webhook test still passes. The gate bites only for a tenant an operator
has put on a plan whose `features` list omits `webhooks`.

A new `402` is added to the problem catalogue as a dedicated slug + factory
(`StarterProblems.PaymentRequired`), the same way the permission and
platform-admin gates own their problems; `ErrorKind` is untouched (this is a
filter-produced block, not a domain error).

## 4a. Gating the permission catalogue

Beyond gating feature endpoints, a plan also bounds which RBAC permissions a
tenant may put in a custom role (multi-tenancy.md sections 15, 21 commit this
increment to it, and section 15 already reserves the seam as "a no-op filter
until billing exists"). The plan's `permissions` list is that catalogue: NULL =
unrestricted (any non-owner-reserved permission is grantable, the pre-billing and
default state); a non-null list closes it to exactly that set.

Enforcement lives where custom roles are authored: `CustomRoleService`'s
create/update permission validation (which already rejects unknown and
owner-reserved permissions) gains one more check - each requested permission must
be `AllowsPermission` under the caller's entitlements, else the write is refused
with a `webhooks`-style upgrade error (`tenancy.permission_not_in_plan`). It
resolves entitlements the same way `GetCallerEntitlementsAsync` does (the tenant's
plan plus `IEntitlementSource`). This is fail-open by the same rule: with the
default NULL-`permissions` plan, every non-owner-reserved permission stays
grantable and no existing custom-role test changes; the gate bites only when an
operator publishes a plan with an explicit `permissions` list. Existing roles that
already hold a now-excluded permission keep working (the check is at authoring
time, not resolution time) - downgrading a plan does not silently strip live
grants; that reconciliation is a documented operator concern, not a runtime
surprise.

## 5. Limits

- **Seat limit** is plan-driven: assigning a plan sets `tenant.seat_limit` from the
  plan's `seatLimit`, so the existing seat check (invitation-accept) needs no
  change and `GetSeatsAsync` now reports a plan-derived number. Because
  `tenant.seat_limit` is NOT NULL, `seatLimit` is REQUIRED on plan create/update:
  a plan whose `limits` omits it (or gives a non-positive value) is rejected at
  plan-write time, so assign-plan can never land a null or zero limit that would
  silently block every future invitation.
- **Other numeric limits** (for example `maxWorkspaces`) are DEFINED here (on the
  plan) and surfaced via `GetLimit`, but their ENFORCEMENT (counting current usage
  against the limit and refusing at the boundary) is the usage-quota increment
  (multi-tenancy.md section 21, "usage quotas"), which owns the metering. This
  increment defines and exposes limits; quotas enforce the countable ones. Seat
  limit is the one already enforced, so it is wired now; the rest are declared.

## 6. Events and audit

- Assigning or changing a tenant's plan emits a tenant-scoped
  `tenancy.tenant.plan_changed` (added to the shared deliverable catalogue, so it
  is audited AND webhook-deliverable), carrying the old and new plan keys (scalars,
  no PII).
- Plan-catalogue edits (create / update a plan) are operator actions not scoped to
  a tenant, so they are written to the platform audit log synchronously through the
  `IPlatformAuditWriter` (audit-log.md section 4), exactly like a super-admin grant
  - transactional with the catalogue write, on the bypass path.

## 7. Super-admin API

On the platform group behind `RequirePlatformAdmin` (cross-tenant, bypass path):

- `GET /api/v1/platform/plans` / `POST /api/v1/platform/plans` /
  `PATCH /api/v1/platform/plans/{key}` - the plan catalogue (list, create, update
  name / features / limits / default). Exactly one plan may be `is_default`
  (enforced app-side on write). Deleting a plan is deliberately NOT offered while a
  tenant references it (retire by editing, or add a migration once no tenant is on
  it) - a dangling `tenant.plan` would silently fail open.
- `POST /api/v1/platform/tenants/{id}/plan` - assign a plan to a tenant (sets
  `tenant.plan` and denormalizes `seat_limit`). This is a NEW `AssignPlanAsync`
  method, not a call into `ChangeTenantStatusAsync` (that helper takes a 3-arg
  status-event factory and flips one field; assign-plan sets two fields and emits
  a plan-changed event carrying old and new keys). It FOLLOWS the same structure:
  a bypass connection bound to the target tenant, one transaction, the EF write,
  the event enqueue, commit. The target plan must exist (a 404 otherwise), so a
  tenant is never assigned a dangling plan key.

Tenants do not author plans (a tenant cannot buy itself a better tier by fiat);
they see their own plan and entitlements through the existing tenant-admin surface
(the seats endpoint, extended to report the plan and its limits). A future
self-serve checkout is the payment-provider seam (section 9), which lands the
tenant on the same assign-plan path after a real payment.

## 8. Placement and deletability

`platform.plans`, `IEntitlementSource`, and the `RequireEntitlement` filter live
in Platform / the Api layer (the catalogue is global operator vocabulary, like the
permission catalogue); the tenant `plan` read and the super-admin assign live in
Tenancy (which owns the tenant row). Deletability: drop `platform.plans`, the
entitlement service, the filter, the `payment-required` problem, and the plan
columns' new mutability, and the tenant keeps a harmless free-text `plan` field
that nothing consults - the pre-billing state.

## 9. The payment-provider seam (documented, not built)

A provider (Stripe, Paddle, ..) owns checkout, the card, and the subscription
lifecycle. Integration is: (1) a checkout link per plan (the provider's hosted
page); (2) an INBOUND webhook endpoint that verifies the provider's signature and,
on `subscription.created/updated/deleted`, calls the assign-plan path (section 7)
to move the tenant to the paid plan (or back to `free` on cancellation); (3) the
provider's customer id stored on the tenant for the billing portal link. None of
this is built - the entitlement model is provider-agnostic, and the assign-plan
path is the single seam a provider drives. This is the same "integrate the
standard, do not hand-roll it" posture as SSO/SCIM.

## 10. Tests (added to the crown-jewel suite)

- **Fail-open by default**: a tenant on the seeded `free` plan (unrestricted) or
  with a null/unknown plan passes `RequireEntitlement("webhooks")`; every existing
  webhook test still passes unchanged.
- **Gating bites on a restrictive plan**: an operator creates a plan whose
  `features` omits `webhooks`, assigns it to a tenant, and that tenant's webhook
  calls get `402 starter:payment-required`; a tenant on an unrestricted plan
  succeeds.
- **Entitlement is orthogonal to permission**: a caller WITH `webhooks:manage` but
  on a restrictive plan is 402 (not 403); a caller on an unrestricted plan WITHOUT
  the permission is 403 (not 402) - the two gates are independent.
- **Plan assignment drives seat limit**: assigning a plan with `seatLimit = 2` sets
  the tenant's seat limit to 2, and the seat check then refuses the third member.
- **Super-admin only**: plan CRUD and assign-plan require `RequirePlatformAdmin`; a
  tenant admin is 403; a tenant cannot change its own plan.
- **RLS isolation**: `GetCallerEntitlementsAsync` reads only the caller's own tenant
  plan; a plan change to tenant A never affects tenant B's resolution.
- **Permission catalogue is plan-gated**: on a plan whose `permissions` list omits
  `roles:manage`, authoring a custom role that includes `roles:manage` is refused
  (`tenancy.permission_not_in_plan`); on the default (NULL) plan the same authoring
  succeeds, and every existing custom-role test stays green.
- **Provisioning follows the default plan**: with `free` seeded default, a new
  tenant lands on `free` with its seat limit; changing which plan is `is_default`
  changes what the next new tenant gets. A second `is_default = true` write is
  rejected by the unique index (or atomically demotes the prior default).
- **seatLimit is required**: creating a plan whose `limits` omits `seatLimit` (or
  gives <= 0) is refused at plan-write time.
- **Audited**: a plan create/update lands a platform-audit row; a tenant plan change
  lands a tenant audit row (and is webhook-deliverable), and catalogue-completeness
  stays green with the new `tenant.plan_changed` type.

## 11. Build sequence (this increment)

1. Migration: `platform.plans` (no RLS), the partial unique index on
   `is_default`, seed the default `free` plan with `features` and `permissions`
   as SQL NULL; the boot-time REVOKE of write on `platform.plans` from the request
   role.
2. `PlanRow` mapped in `PlatformDbContext` (no tenant filter); make `Tenant.Plan`
   and `Tenant.SeatLimit` settable; `TenantProvisioner` reads the `is_default`
   plan (key + seatLimit) instead of the hardcoded literal, falling back to
   `free` / 5.
3. `Entitlements` value object (`Features`, `GrantablePermissions`, `Limits`) +
   `IEntitlementSource` (Platform, per-resolve catalogue read, fail-open).
4. `ITenancyApi.GetCallerEntitlementsAsync` (RLS read of the tenant plan +
   resolve); extend the seats/tenant view to report the plan and its limits; wire
   the `AllowsPermission` check into `CustomRoleService` create/update
   (`tenancy.permission_not_in_plan`, fail-open on a NULL list).
5. `RequireEntitlement` filter + `ProblemTypes.PaymentRequired` +
   `StarterProblems.PaymentRequired` (402); gate the webhook endpoints with
   `RequireEntitlement("webhooks")`, composed AFTER `RequirePermission`.
6. Super-admin plan CRUD (with the exactly-one-default + required-positive
   -seatLimit validation) + a new `AssignPlanAsync` (bypass, target-bound), setting
   `seat_limit` from the plan; `tenancy.tenant.plan_changed` added to
   `DeliverableEvents`; plan-catalogue edits audited via `IPlatformAuditWriter`.
7. Tests (section 10) in the integration suite.
