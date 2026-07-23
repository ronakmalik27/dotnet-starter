# Usage quotas

Status: DESIGN (proposed). The sixth SaaS grow-into feature (multi-tenancy.md
section 21, "usage quotas"). Docs-first: nothing here is built until this
revision is reviewed. This increment is the enforcement half of the split the
billing increment named: billing-and-entitlements.md section 5 DEFINES and
exposes a plan's numeric limits (`seatLimit`, `maxWorkspaces`, ..) and says their
ENFORCEMENT - counting current usage against the limit and refusing at the
boundary - is "the usage-quota increment, which owns the metering". This doc owns
that. Read billing-and-entitlements.md section 5 first.

## 1. The decision, up front

- **A quota enforces a plan's numeric LIMIT; it is a commercial gate, so it FAILS
  OPEN like an entitlement, not closed like a security gate.** A quota answers
  "have you used more of this than your plan allows". When the plan declares NO
  limit for a metric, the metric is unlimited and the check is a no-op - the same
  fail-open default as entitlements (billing-and-entitlements.md section 1): an
  unconfigured or paying-by-default starter is never locked out of its own
  product. Enforcement engages ONLY once an operator publishes a plan that names a
  finite limit for the metric.
- **Two kinds of quota, because SaaS products meter two different things.**
  - A RESOURCE-COUNT quota (a gauge) bounds how many of a thing may exist at once:
    workspaces, teams, webhook endpoints, service accounts. Enforced at CREATE
    time by counting the tenant's current rows and refusing at the ceiling. The
    seat limit (invitation-accept) is the prototype already shipped; `maxWorkspaces`
    is the worked example this increment wires live. Not temporal: waiting does
    not free a slot, so the honest answer is 402 (upgrade) or delete something.
  - A METERED quota (a windowed counter) bounds consumption over a billing period:
    API calls, events processed, emails sent, jobs run. Enforced by an atomic
    counter incremented on use and compared to the limit; it RESETS each period.
    Temporal, so the honest answer is 429 with `Retry-After` (the period reset).
    This is the metered-billing shape (Stripe usage records, Twilio, GitHub API).
- **HARD enforcement (reject at the ceiling) is what ships; SOFT (allow the
  overage, record it for usage-based billing) is a documented grow-into.** The
  metered counter records usage regardless; hard mode adds the reserve-and-refuse.
  A soft/overage mode is the same counter without the guard clause, plus a billing
  hook - named in section 9, not built.
- **Limits are resolved from the tenant's plan, never hard-coded.** Both kinds read
  the tenant's resolved `Entitlements.Limits` (billing-and-entitlements.md section
  3): `maxWorkspaces` for the resource gauge, an arbitrary metric key for a metered
  quota. `Entitlements` already carries `Limits` and `GetLimit`; a metric absent
  from `Limits` means unlimited (fail open).
- **Quotas are NOT the edge rate limiter.** The existing per-IP rate limiter
  (Program.cs) protects the service from abuse at the edge: a token bucket over
  seconds, keyed on the caller's IP, indifferent to tenant or plan. A usage quota
  is a per-TENANT, plan-driven count over a billing period. They are both
  throttles and they compose (an abusive caller is stopped by the rate limiter
  first), but they answer different questions and share no mechanism. The section
  21 catalogue's shorthand "quotas ride the rate limiter" is superseded by this
  doc: a plan-driven monthly counter is not a token bucket.

## 2. Data model

`platform.usage_counters`, tenant-owned, RLS (`ITenantOwned` + FORCE RLS + the
standard `tenant_isolation` policy). One row per (tenant, metric, period); the
metered counter only. Resource-count quotas need no table - they count the
resource's own rows.

| column | type | notes |
|---|---|---|
| `tenant_id` | uuid not null | the RLS discriminator, stamped from context on write |
| `metric` | text not null | the metered metric key (matches a plan `limits` key) |
| `period_start` | date not null | the UTC first-of-month anchor of the billing period |
| `used` | bigint not null | consumption in this period; `bigint` so a high-volume metric cannot overflow |
| `updated_at` | timestamptz not null | last increment |

- PRIMARY KEY `(tenant_id, metric, period_start)`. No partial-index / NULLS games:
  every column is NOT NULL, so a plain composite PK is the upsert conflict target.
- Hosted in `PlatformDbContext` (cross-cutting metering, like the audit log and
  webhooks live in Platform), tenant-owned under RLS. This is a normal request/
  consumer-path table: the request role keeps INSERT/UPDATE/SELECT (no REVOKE), so
  a tenant's own request increments its own counter under RLS. There is nothing
  operator-owned here, unlike `platform.plans` or `platform.feature_flags`.
- Old-period rows are harmless history (usage trend). Pruning them is an operator
  job (a documented grow-into, section 9); nothing reads a period but the current
  one.

## 3. The period

- The billing period is the CALENDAR MONTH in UTC. `PeriodStart(now)` is the
  first of `now`'s month at 00:00:00 UTC (a `date`); `ResetAt(now)` is the first
  of the next month at 00:00:00 UTC. A metered quota's window is
  `[PeriodStart, ResetAt)`.
- Computed in application code from `Clock.UtcNow` (never `DateTime.UtcNow` - the
  banned-API arch test forbids it), so tests can pin the clock and cross a period
  boundary deterministically.
- A per-tenant billing ANCHOR (align the reset to each tenant's signup day, not
  the calendar) and ROLLING windows (last-30-days) are documented grow-into
  (section 9), not built. Calendar-month matches Stripe's default cycle and keeps
  the period key a stable, index-friendly `date`.

## 4. The metered quota service (Platform)

`IQuotaService` in `Starter.Platform`, request-scoped, resolves the request-scoped
`PlatformDbContext` (RLS-bound to the active tenant, exactly like the feature-flag
evaluator and entitlement source). It owns the counter mechanics only; it does NOT
resolve the plan - the caller passes the resolved limit in. This keeps Platform
free of any Tenancy reference (Platform cannot read the plan; the plan lives
behind `ITenancyApi`).

```
Task<QuotaOutcome> TryConsumeAsync(string metric, long amount, int? limit, CancellationToken ct);
Task<IReadOnlyList<MeteredUsage>> GetUsageAsync(IReadOnlyCollection<string> metrics, CancellationToken ct);
```

- `TryConsumeAsync`:
  - `limit is null` -> FAIL OPEN: the metric is unlimited, so this is a true no-op
    - it writes NOTHING and returns `Allowed(used: 0, limit: null, resetAt)`. A
    hard quota with no configured limit has nothing to enforce, and writing a
    counter row on every request to an unlimited metric is pure write
    amplification. (Metering usage WHILE unlimited, to drive overage billing, is
    soft mode - section 9 - not this hard gate.)
  - `limit is not null` -> HARD enforce with an atomic reserve. The counter row for
    the current period must exist, then a GUARDED increment refuses at the ceiling:

    ```sql
    insert into platform.usage_counters (tenant_id, metric, period_start, used, updated_at)
    values (@tenant, @metric, @period, 0, @now)
    on conflict (tenant_id, metric, period_start) do nothing;

    update platform.usage_counters
       set used = used + @amount, updated_at = @now
     where tenant_id = @tenant and metric = @metric and period_start = @period
       and used + @amount <= @limit
    returning used;
    ```

    The `UPDATE` takes a row lock, so concurrent requests serialize on it - the
    reserve is atomic and cannot oversell the limit (no check-then-act race). If it
    returns a row, the amount was consumed -> `Allowed(used, limit, resetAt)`. If it
    returns ZERO rows, the increment would breach the ceiling -> nothing was
    consumed (the guard blocked the write) -> `Denied(used, limit, resetAt)`, where
    `used` is re-read (the current value, unchanged). `tenant_id` is stamped from
    the context and RLS `WITH CHECK` rejects any cross-tenant write.
  - `amount` MUST be positive; guard it (`ArgumentOutOfRangeException` on `<= 0`).
- `GetUsageAsync` returns the current-period `used` for each requested metric (0
  for a metric with no row yet), for the usage report. RLS-scoped read.
- `MeteredUsage(string Metric, long Used)`; `QuotaOutcome` carries
  `bool Allowed, long Used, int? Limit, DateTimeOffset ResetAt`.

Registered in `PlatformPersistence` (scoped), like `IFeatureFlagEvaluator`.

## 5. The metered endpoint gate (`RequireQuota`)

`RequireQuota(metric, amount = 1)` in the Api-layer `PermissionGate` (next to
`RequireEntitlement`), an endpoint filter factory. Like `RequireEntitlement`, it
lives in the Api layer because it must resolve `ITenancyApi` for the plan limit.

- Resolve the active tenant's entitlements via
  `ITenancyApi.GetCallerEntitlementsAsync` (the same call `RequireEntitlement`
  uses). Read the metric's limit with `Entitlements.Limits.TryGetValue(metric, out
  var value) ? value : (int?)null` - present -> `int?` limit; absent -> `null`
  (unlimited, fail open). Do NOT use `Entitlements.GetLimit(key, fallback)`: it
  returns a non-nullable `int` and cannot distinguish "absent" from
  "present-with-fallback", so an absent limit would collapse to the fallback -
  either a deny-all `0` (locking every default-plan tenant out) or a bogus
  "unlimited" that defeats a legitimate `limit = 0` (deny-all) plan. The absent
  ==> unlimited invariant is load-bearing (section 1); read it with `TryGetValue`,
  matching the existing `limits.TryGetValue("seatLimit", ..)` idiom in
  `PlatformAdminService`.
- Call `IQuotaService.TryConsumeAsync(metric, amount, limit)`.
  - `Allowed` -> `await next` (proceed).
  - `Denied` -> short-circuit `429 Too Many Requests`, problem type
    `starter:quota-exceeded` (metered-only; the resource-count refusal in section 6
    uses a DISTINCT slug at 402, so each problem type keeps this codebase's strict
    one-type-one-status contract). Set the `Retry-After` header to the whole
    seconds until `ResetAt` (never negative; clamp at 0). The problem detail names
    the metric, the limit, and the reset instant so a client can back off precisely.
- Compose AFTER `RequireTenant` (a no-tenant request answers 400 tenant-required
  first), AFTER `RequirePermission` (an unauthorized caller gets 403 before the
  quota is consulted), and AFTER any `RequireEntitlement` (a plan that does not
  include the feature answers 402 before the quota is consulted). `RequireQuota`
  goes LAST because it is the only WRITE in the chain: every cheaper, read-only
  rejection (permission, then entitlement) must run first, so a request that was
  always going to be rejected never burns a unit of the tenant's metered budget.
  Ordering: group `RequireTenant` + `RequireAuthorization`, then route
  `RequirePermission`, then `RequireEntitlement`, then `RequireQuota`.
- Consuming a quota is a WRITE (it increments the counter). Apply `RequireQuota`
  only to endpoints that should count against a metered budget, and count them once
  per request. A GET that is merely reporting usage never carries `RequireQuota`.

### Worked metered example (config-gated demo route)

Exactly the feature-flag gate-demo pattern (feature-flags.md section 4): the filter
factory must run at map time, so a dedicated demo route
`/api/v1/tenant/quota-demo` gated by `RequireQuota("demo_calls")` maps ONLY when
`Quotas:DemoEnabled` is set (the integration-test host sets it; production never
maps it, so no live route carries a metered quota by default). The metered test
publishes a plan whose `limits.demo_calls` is small, assigns it, calls the route to
the ceiling (each 200), gets a 429 with `Retry-After` at the ceiling, pins the
clock into the next month, and sees the counter reset (200 again). Feature flags
proved the same map-time-filter constraint; this reuses the established shape
rather than retrofitting a live route.

## 6. The resource-count quota (`maxWorkspaces`, wired live)

- Enforced at workspace CREATE in `WorkspaceService` (Tenancy). NOTE the seat
  check is NOT the mechanism to copy: seats reads a DENORMALIZED `tenant.seat_limit`
  int column via raw SQL on the bypass path under a `SELECT .. FOR UPDATE` row lock
  (`InvitationAcceptor`); there is no denormalized `max_workspaces` column.
  `maxWorkspaces` comes from the plan, so resolve it the way
  `TenantAdminService.GetCallerEntitlementsAsync` does: read the active tenant's
  `Plan` under RLS, then `IEntitlementSource.ResolveAsync(planKey)` to get
  `Entitlements`, then read the limit with `Limits.TryGetValue("maxWorkspaces", out
  var value)` (NOT `GetLimit`, per section 5 - absent must stay distinguishable
  from present-with-fallback):
  - absent -> unlimited (fail open), create proceeds unchanged;
  - present -> count the tenant's CURRENT workspaces under RLS; if the count is
    already at or above the limit, REFUSE with error code
    `tenancy.workspace_quota_reached` before inserting; else create.
- **Wiring** (`WorkspaceService` has no build-sequence sibling doc, so it is spelled
  out here). `WorkspaceService` today injects `TenancyDbContext`, `ITenantContext`,
  `OutboxWriter`, `Clock`; it gains an `IEntitlementSource` (a Platform service the
  Tenancy module may reference, exactly as `TenantAdminService` already does).
  Inside `CreateWorkspaceAsync`, AFTER the slug/name validation: (1) resolve the
  caller's entitlements (the `GetCallerEntitlementsAsync` pattern - the plan read is
  RLS-bound and, like `GetSeatsAsync`, the no-RLS catalogue resolve can follow the
  tenant read); (2) if `maxWorkspaces` is present, open the create transaction,
  `CountAsync` the tenant's workspaces under RLS, refuse at the ceiling; (3) else
  insert as today. The count and insert share the create transaction, so the count
  is RLS-scoped to the tenant and the ceiling is per tenant.
- A brief create-create race could in principle admit one workspace over the
  ceiling under extreme concurrency. Workspace creation is human-paced, so unlike
  the seat race this does NOT take the `FOR UPDATE` tenant-row lock (the resource
  -gauge norm). If a product needs the hard guarantee, take the same tenant-row
  `FOR UPDATE` the seat check uses - noted in section 9.
- The Api maps `tenancy.workspace_quota_reached` to `402 Payment Required`, problem
  type `starter:resource-quota-reached` - a DISTINCT slug from the metered
  `starter:quota-exceeded` (429), keeping this codebase's strict one-problem-type
  -one-HTTP-status contract (402 says "upgrade or delete something", 429 says "wait
  for the period reset"; a client dispatching off `type` alone must not have to
  branch on `status`). Wire it in `TenancyProblems.cs`, the per-module error-code
  switch, next to the existing `tenancy.permission_not_in_plan => 402` case it
  mirrors. The seat limit keeps its own dedicated `starter:tenant-seat-limit-reached`
  (409) - it predates this generalized quota, and re-badging a security-adjacent,
  race-proof path buys nothing. Seats and the generalized resource quota coexist;
  seats is the prototype.

## 7. The usage report

`GET /api/v1/tenant/usage`, gated `RequirePermission(seats:read)` (reusing the
existing read permission that already gates `/seats`; usage and seats are the same
"what am I consuming vs my plan" question, so no new permission atom and no plan
-catalogue churn). Returns, for the active tenant under RLS:

- `limits`: the plan's declared numeric limits (`Entitlements.Limits`), verbatim.
- `metered`: for each KNOWN METERED metric, its current-period `used`, its `limit`
  (or null = unlimited), and `resetAt`. The metered set is a code-side list (today
  just `demo_calls`, the one shipped metered metric), NOT "every plan-limit key":
  `seatLimit` and `maxWorkspaces` are RESOURCE-count limits, so they belong under
  `resources` (with a real current count), never under `metered` with a meaningless
  `used: 0` that reads as "metered, no activity this period". A product adds a new
  metered metric by adding its key to that code-side set (and a `RequireQuota` on
  its route). When `limit` is null the metric is unlimited and NOT metered (section
  4's no-op), so surface `used` as null / "not tracked", not a bare 0. A response
  consumer keys off `limit == null`.
- `resources`: the resource-count gauges - `workspaces` (current count vs
  `maxWorkspaces`) and `seats` (active members vs `seatLimit`, reusing
  `GetSeatsAsync`) - each `{ metric, used, limit }`.

This is the standard usage dashboard (Vercel, LaunchDarkly). It composes in the Api
layer from `ITenancyApi` (limits + resource counts) and `IQuotaService` (metered
usage); neither service reaches across the module boundary.

## 8. Events and audit

- Quota consumption is high-frequency and NOT a domain event; the counter row is
  the state. Nothing is written to `domain_events` per consume.
- A quota REJECTION is a real business signal (upsell, alerting), but emitting an
  event per rejection risks an outbox flood on a hot metered endpoint at its
  ceiling. So NO `tenancy.quota.exceeded` event ships this increment. The usage
  counter row already holds the state a notification needs; a throttled
  "limit reached" notice (at most once per period, driven off the counter) is the
  in-app-notifications increment's job (multi-tenancy.md section 21), reading this
  state - a documented hook, section 9. This keeps the deliverable-events catalogue
  unchanged and avoids a flood surface.
- Plan-limit CHANGES are already audited: assigning or editing a plan emits
  `tenancy.tenant.plan_changed` / writes the platform audit log
  (billing-and-entitlements.md section 6). A tenant's effective limits change only
  through those already-audited operator actions, so there is no audit gap.

## 9. Deferred (documented grow-into, not built)

- SOFT / overage mode: the same counter without the guard clause, recording the
  overage, plus a billing hook that reports usage records to the payment provider
  (Stripe usage-based billing). The counter is built soft-ready (it records before
  the guard); only the guard and the billing bridge differ.
- A throttled "limit reached" / "approaching limit" (for example 80%) notification,
  at most once per period, read off `usage_counters` by the in-app-notifications
  increment.
- Per-tenant billing ANCHOR (reset aligned to each tenant's signup day) and ROLLING
  windows (last-N-days), instead of the calendar month.
- Old-period counter PRUNING (a scheduled job) once usage history is large.
- A hard concurrency guarantee on the resource-count race (the tenant-row
  `FOR UPDATE` the seat check uses), if a product needs a resource gauge to be
  race-proof rather than human-paced.
- More metered metrics and more resource gauges: the model is generic (any plan
  `limits` key), so a new quota is a new limit key plus a `RequireQuota` on the
  metered route or a count-check at the resource's create site - no schema change.

## 10. Deletability

The whole increment is additive and removable with no residue: drop
`platform.usage_counters` + its migration, `IQuotaService` / `QuotaService`,
`RequireQuota` + the demo route, the `/usage` endpoint, and the `maxWorkspaces`
check in `WorkspaceService`. The seat quota and everything from the billing
increment are untouched. Nothing else references quotas.
