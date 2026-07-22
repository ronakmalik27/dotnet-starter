# Multi-tenancy and the SaaS control plane

Status: DESIGN (proposed). This is the blueprint the tenancy build follows.
It is docs-first by rule: nothing below is built until this doc is reviewed.
This revision incorporates a security red-team pass (the isolation boundary,
the async consumer path, the bypass path, provisioning atomicity, invitation
and seat handling).

This starter ships single-tenant by default. This document specifies the
optional but first-class SaaS layer: tenant isolation, tenant-scoped roles
(RBAC), tenant onboarding, a tenant-admin control-plane API, and a platform
super-admin plane with audited impersonation. It is written so the whole layer
can be deleted (drop `Starter.Tenancy`, the platform tenant-context pieces, and
the control-plane endpoints) and leave the generic backend intact.

## 1. The decision, up front

- **Isolation model: shared database, shared schema, a `tenant_id` discriminator
  on every tenant-owned row, enforced by PostgreSQL Row-Level Security (RLS) as
  the authoritative boundary, with EF Core global query filters as a second,
  ergonomic layer.** This is the "pool" end of the AWS SaaS Factory pool/silo
  spectrum, the default the large majority of B2B SaaS run. RLS puts us above
  the common bar: most app-tier tenant filtering leaks the first time a developer
  forgets a `WHERE tenant_id = ...` or drops to raw SQL. RLS enforces isolation
  in the database, so a forgotten filter cannot cross tenants. We keep the EF
  global filter too, because it is fast and ergonomic: defense in depth, not
  either/or.
- **One place sets the tenant: a transaction-start interceptor.** Every
  tenant-scoped unit of work runs inside a transaction, and a single
  `IDbTransactionInterceptor` issues `SET LOCAL app.current_tenant` when that
  transaction starts. Reads, idempotent mutations, non-idempotent mutations, and
  event consumers all go through it, so the tenant GUC is always
  transaction-scoped and a pooled connection can never carry one request's tenant
  into another's. This is the load-bearing mechanism; sections 2 and 5 build on it.
- **The token stays thin.** The access JWT gains exactly one claim, `tid` (the
  active tenant), and still carries no roles. A caller's role in the active
  tenant is resolved per request from the membership table, exactly as
  per-resource ownership is resolved today. We extend the existing authorization
  philosophy; we do not reverse it.
- **Users are global; membership is per-tenant.** One `identity.users` account
  can belong to many tenants, like a GitHub account across organizations or a
  Slack account across workspaces. Identity barely changes; tenancy is a new,
  separate module.
- **Crossing tenants is a role, not a flag.** The control plane, migrations,
  provisioning, and the few genuinely cross-tenant background jobs run as a
  distinct, RLS-bypassing Postgres role reached through a separate connection
  source that request-scoped code cannot obtain. There is no in-band "bypass"
  switch.

## 2. Isolation: how RLS is wired

Every tenant-owned table gets `tenant_id uuid not null`. A migration enables RLS
and adds one policy covering all verbs:

```
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON <t>
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
```

`FORCE` is mandatory: the app connects as the table's owning role, and without
`FORCE` the owner silently bypasses RLS, defeating the boundary. The `true`
second argument to `current_setting` makes a missing GUC return NULL instead of
erroring, so any query with no tenant set is fail-closed: SELECT/UPDATE/DELETE
match zero rows, and an INSERT with a NULL comparison fails `WITH CHECK`.

**Setting the tenant (the one seam).** A single `IDbTransactionInterceptor`
overrides `TransactionStartedAsync` and executes
`SET LOCAL app.current_tenant = @tid`, reading `@tid` from a request-scoped
`ITenantContext`. Because it is `SET LOCAL`, the value lives exactly for that
transaction and is gone when the transaction ends, independent of Npgsql's
connection-reset behavior. This is why every tenant-scoped code path must run
inside a transaction:

- Idempotent mutations already open a transaction (the idempotency filter); the
  interceptor fires there.
- Non-idempotent mutations (for example the Sample DELETE, and the standalone
  branch of a create handler) open their own transaction; the interceptor fires
  there too.
- Reads that are transactionless today (`GetNote`, `ListNotes`) are changed to
  open an explicit read transaction, so they are covered. A read with no tenant
  context is fail-closed (zero rows), never a leak.

We deliberately do not use a connection-open interceptor with session-level
`SET`, because a single missed reset on a pooled connection is a cross-tenant
leak, and `SET LOCAL` outside a transaction is a silently-ignored no-op.

**The EF filter (ergonomics, not the boundary).** Tenant-owned entities
implement `ITenantOwned` (`Guid TenantId { get; }`). Each module's `DbContext`
applies `HasQueryFilter(e => e.TenantId == EF.Property...)` referencing a
DbContext instance member (not a captured closure value), so the compiled-model
cache cannot bake in the first request's tenant even though `DbContextOptions`
is registered as a singleton. Writes stamp `TenantId` from `ITenantContext`,
never from client input. RLS remains the authority: it catches raw SQL,
`FromSqlRaw`, projections, and a stale or absent filter alike. The filter is
there to keep the common path honest and queries readable, and its correctness
is never relied on for the security boundary.

**Crossing tenants safely.** The control plane, migrations, provisioning, and
the small set of genuinely cross-tenant platform consumers run as a separate
Postgres role with `BYPASSRLS` (or the owner plus a permissive policy), reached
through a distinct `NpgsqlDataSource` that is not registered where request-scoped
code can resolve it. There is no `app.bypass_rls` GUC or any other in-band
switch, because a namespaced GUC is settable by any role on its own session and
would reintroduce the exact app-discipline bypass RLS exists to prevent. An
isolation test asserts that a normal request-role session cannot read another
tenant's rows by any means, including attempting to set a bypass GUC.

## 3. The async / event-consumer path

The outbox is the spine of the architecture and consumers are first-class, so
they get the same authoritative isolation as HTTP requests, not a bypass.

- **Events carry their tenant.** `domain_events` and the outbox row gain
  `tenant_id uuid`. It is not-null for an event emitted by tenant-owned work and
  null only for a genuinely platform-level event. The emitter stamps it from the
  ambient `ITenantContext` at enqueue time.
- **Consumers run under the tenant GUC.** Before a tenant-scoped consumer opens
  its consume transaction, the dispatcher sets a consumer-scoped `ITenantContext`
  from the event's `tenant_id`; the same transaction-start interceptor (section
  2) then issues `SET LOCAL app.current_tenant`. So a consumer reading or writing
  a tenant-owned projection is bound by RLS exactly like a request, and a
  consumer that forgets to filter still cannot cross tenants. The dedup claim
  (`ProcessedEventStore`) and any consumer write run under that same GUC.
- **Platform consumers are the exception, marked as such.** A consumer that must
  legitimately span tenants declares that explicitly and runs on the bypass data
  source (section 2). This is a small, named set, never the default for
  "background work".

## 4. Tenant context resolution and the token

`TenantResolutionMiddleware` establishes a request-scoped `ITenantContext`.
Sources, in a configurable order (default first):

1. The `tid` claim on an authenticated access token (authoritative once signed
   in).
2. Subdomain host (`acme.app.example.com` -> slug `acme`).
3. Path prefix (`/t/{slug}/...`).
4. `X-Tenant` header (useful for API clients and tests).

A tenant-scoped request with no resolvable tenant is a 400 with a stable
`starter:tenant-required` problem. A request whose `tid` does not match a
membership the caller still holds is a 403.

The access token gains `tid` and still carries no role. A user in several
tenants selects one (`POST /api/v1/tenants/{id}/token` or a tenant switch) and
the new access token is minted for that tenant; refresh preserves it. The
membership-still-held check is enforced at mint as well as per request, so a
revoked member cannot mint or keep using a `tid` token for a tenant they left.

## 5. Authorization: three layered checks

Authorization for a tenant-scoped request composes three independent layers, in
order:

1. **Tenant boundary** (RLS + the `tid` claim + the EF filter). The caller only
   ever sees rows of the active tenant, enforced below the application.
2. **Tenant role capability** (RBAC), an endpoint filter in the
   `RequireVerifiedEmail` / `RequireTenant` idiom: `RequireTenantRole(minimum)`
   resolves the caller's membership role in the active tenant (per request, from
   `tenancy.memberships` under RLS) and 403s below the minimum with a stable
   `starter:tenant-role-required` problem. `owner > admin > member`. Member
   management and invitations require `admin` or above; `DeleteTenant` and
   `TransferOwnership` require `owner`. The gate resolves the role through
   `ITenancyApi` on `http.RequestServices`, so the capability check stays a
   transport-layer concern like the other endpoint gates, not a policy handler.
3. **Resource ownership** (the `IAuthorizationService` model). The existing
   `ResourceOwnerAuthorizationHandler` (unchanged) grants the resource owner, and
   a second `TenantAdminResourceAuthorizationHandler` also grants a caller who is
   `admin` or above in the active tenant (resolved through a platform-level
   `ITenantRoleReader` seam the Tenancy module implements). ASP.NET Core grants
   if any handler succeeds, so the effective rule is owner OR tenant-admin+: a
   `member` still only manages resources they own; an `admin` may manage any
   resource in the tenant. Ownership is the inner check.

The role is read per request from `tenancy.memberships`, cached per request. The
token carries no roles: same "resolve authorization per request against the
data" stance the starter already takes for ownership.

## 6. Data model

New module `Starter.Tenancy` (schema `tenancy`):

- `tenancy.tenants`: `id`, `slug` (unique citext), `name`, `status`
  (`active` | `suspended` | `deleted`), `plan`, `seat_limit`, `created_at`,
  `created_by`. Soft-delete via status; never a hard row delete (audit). Under
  RLS keyed on `id = current_tenant` for tenant reads; created and administered
  on the bypass path.
- `tenancy.memberships`: `id`, `tenant_id`, `user_id`, `role`
  (`owner` | `admin` | `member`), `status` (`active` | `suspended`),
  `invited_by`, `created_at`. Unique `(tenant_id, user_id)`. Tenant-owned, under
  RLS.
- `tenancy.invitations`: `id`, `tenant_id`, `email` (citext), `role`,
  `token_hash`, `expires_at`, `accepted_at`, `invited_by`, `created_at`. The raw
  invite token reaches the invitee only through the emailed link, never on the
  event spine (mirrors the verify-email and password-reset one-time-token
  pattern already in Identity). Read by `token_hash` on the bypass path at accept
  time (section 8), since the invitee is not yet a member.

Platform-level (schema `platform`, not tenant-scoped, no RLS):

- `platform.platform_admins`: `user_id`, `granted_by`, `granted_at`. The
  cross-tenant operators, deliberately tiny and separate from tenant membership,
  so platform power is never a tenant role. The first admin is an out-of-band
  seed (a migration or an ops command), never self-granted through the API.
- `platform.impersonation_grants`: `id`, `platform_admin_user_id`,
  `target_tenant_id`, `target_user_id` (nullable), `reason`, `issued_at`,
  `expires_at`, `ended_at`. The audit spine for section 7.

`domain_events` / outbox gain `tenant_id uuid` (section 3).

Existing `Starter.Sample` is migrated to tenant-owned: a note is scoped to its
tenant and still owned by its creator inside that tenant. Sample is the worked
example of a tenant-aware module (RLS + query filter + owner check layered).

## 7. Platform super-admin plane and impersonation

A separate authorization plane, gated by `RequirePlatformAdmin` (backed by
`platform.platform_admins`), never by a tenant role. Platform-admin endpoints
run on the bypass data source (section 2). Surface: list/search tenants; view a
tenant; suspend, reactivate, soft-delete a tenant; list and grant/revoke platform
admins; start and stop an impersonation session.

**Impersonation is audited, time-boxed, and revocable.** A platform admin starts
an impersonation with a target tenant (and optionally a target user) and a
written reason. In one transaction the server writes a
`platform.impersonation_grants` row and emits `ImpersonationStarted` on the
outbox, then mints a short access token (lifetime <= the 15-minute access cap)
carrying `tid` for the target tenant plus an `imp` claim naming the acting
platform admin. Because the grant row and the event are written in the same
transaction, no impersonation token can exist without its audit row. Because
`imp` is a signed claim, it is unforgeable and attributable. Because every
`imp`-bearing request re-checks the grant (`ended_at IS NULL AND now() <
expires_at`), ending a session early takes effect immediately, not only at token
expiry. Under `imp`, destructive or irreversible operations may be refused (a
conservative default the app tightens per endpoint). The grant auto-expires at
its absolute cap with no rotation; ending it writes `ended_at` and emits
`ImpersonationEnded`.

## 8. Tenant-admin control-plane API and provisioning

Tenant-admin endpoints are gated by `RequireTenantRole(admin)` (owner-only where
noted), all tenant-scoped:

- Invite a member (`email`, `role`); emails the invite link.
- List and revoke pending invitations.
- List members; change a member's role; remove a member. Owner-only: transfer
  ownership, soft-delete the tenant.
- Update tenant settings (`name`, `slug`).
- View seats and usage.

**Accepting an invitation is its own endpoint, not a tenant-admin one.** The
invitee is by definition not yet a member and holds no role or `tid` for the
target tenant, so it cannot sit behind `RequireTenantRole`. It is authorized by
possession of the (hashed, single-use, expiring) invite token plus an
authenticated user id. The server reads the invitation by `token_hash` on the
bypass path, then, in one transaction, re-checks the seat limit under a row lock
on the tenant (`SELECT ... FOR UPDATE`, so two concurrent accepts cannot overrun
`seat_limit`), creates the `active` membership, consumes the token, and emits
`MembershipCreated`.

**Provisioning a new tenant is a control-plane operation on the bypass path.**
Creating a tenant establishes a new boundary, so it necessarily runs before any
tenant context exists and cannot be an ordinary tenant-scoped request. Two entry
points:

- **Self-serve.** An anonymous, rate-limited signup creates the user, the
  tenant, and the caller's `owner` membership atomically in one transaction on
  the bypass data source, emitting `TenantCreated` and `MembershipCreated` on the
  outbox. It is atomic because all three writes share one connection and
  transaction (the same enlist-a-second-context-on-one-connection pattern the
  outbox already uses). If staging Identity's write on that shared transaction
  proves too invasive, the documented fallback is: create the user through the
  normal flow, then provision the tenant idempotently on the first authenticated
  request, treating a transient "user with no membership" as a benign state
  identical to an invited-but-unaccepted user. The primary path is preferred.
- **Invited.** An invitee accepts into an existing tenant (above); no new tenant
  is created, and their account is provisioned by the normal Identity flow if it
  does not exist yet.

## 9. Tests: isolation is the crown jewel

The integration suite (real host + Postgres Testcontainer) must include, and the
build is not done until it is green:

- **Cross-tenant leakage.** A token for tenant A gets 404 (not 403, to avoid
  confirming existence) on every tenant B resource: read, update, delete, and
  list (B's rows never appear in A's list). A raw query on the request role with
  the wrong or missing GUC returns zero rows, proving RLS and not just the EF
  filter. A test interleaves many tenants across the connection pool to prove no
  pooled connection carries a stale tenant.
- **Bypass containment.** A normal request-role session cannot read another
  tenant by any means, including setting a bypass GUC; only the separate bypass
  data source crosses tenants.
- **Consumer isolation.** A tenant-scoped consumer processing tenant A's event
  cannot read or write tenant B's rows; a platform consumer marked cross-tenant
  can.
- **RBAC.** A `member` is refused member-management (403); an `admin` is granted
  it; owner-only operations refuse an `admin`.
- **Ownership within a tenant.** A `member` cannot edit another member's
  resource; an `admin` in the same tenant can.
- **Impersonation.** Starting one writes the grant row and emits the event; the
  minted token carries `imp`; a refused destructive op under `imp` is refused;
  ending a grant early blocks the next `imp` request immediately; the grant
  expires at its cap.
- **Provisioning and invitations.** Self-serve signup creates tenant plus owner
  membership atomically (a failure leaves neither); invite acceptance creates the
  membership and consumes the token exactly once; two concurrent accepts cannot
  exceed `seat_limit`.

## 10. Placement and the silo escape hatch

- `Starter.Platform` gains the cross-cutting primitives only: `ITenantContext`,
  the `ITenantOwned` convention, the transaction-start GUC interceptor, the
  tenant-resolution middleware, the bypass data source, and the platform-admin
  authorization. These must live in Platform because every module's `DbContext`
  depends on the tenant filter, and Modules depend on Platform, not the reverse.
- `Starter.Tenancy` is the new module: tenants, memberships, invitations,
  provisioning, and the tenant-admin and platform control-plane commands behind
  its `ITenancyApi`.
- `Starter.Sample` is migrated to tenant-owned as the copy-me example.
- `Starter.Identity` is nearly untouched: users stay global. The additions are
  minting `tid` into the access token for a selected tenant, and a seam to stage
  a registration on a provided transaction for atomic self-serve provisioning.
- Deleting the SaaS layer: remove `Starter.Tenancy`, revert Sample to
  owner-only, drop the Platform tenant pieces, the `tid` claim, and the bypass
  data source. The rest of the starter does not depend on any of it.

**Silo path.** Because a module `DbContext` is constructed with a connection and
a schema, moving an isolation-sensitive tenant to its own schema or database is a
change in how that tenant's connection is resolved (a per-tenant connection
factory keyed off `ITenantContext`), not a change to any module's code. The
shared-schema RLS model stays the default; the interceptor and the query filter
become redundant-but-harmless under a silo, so a mixed fleet (most tenants
pooled, a few siloed) is supported without a fork.

## 11. Build sequence

Built and gated in reviewable increments, never one commit:

1. Platform tenant primitives: `ITenantContext`, `ITenantOwned`, resolution
   middleware, the transaction-start GUC interceptor, the EF filter convention,
   the bypass data source, and `tenant_id` on the event spine. Migrate Sample to
   tenant-owned and make its consumers tenant-scoped. Cross-tenant, bypass, and
   consumer isolation tests. This is the security foundation and lands first,
   proven by tests, before any higher-level feature.
2. `Starter.Tenancy` model plus self-serve provisioning and the `tid` token
   mint. Provisioning tests.
3. RBAC: memberships, the tenant-role handler, tenant-admin member and
   invitation APIs (including accept and seats). RBAC, ownership-within-tenant,
   and seat-race tests.
4. Platform super-admin plane and audited impersonation. Impersonation tests.

Each increment is a `/review-gate` pass, a blocking-reviewer pass, and a
`/pre-merge-gate` before merge, exactly like every other change.
