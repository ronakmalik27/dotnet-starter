# Multi-tenancy and the SaaS control plane

Status: Part I (sections 1-11) is BUILT and shipped in four gated increments:
tenant isolation, tenant-scoped roles, provisioning, the tenant-admin control
plane, and the platform super-admin plane with audited impersonation. Part II
(sections 12 onward) is DESIGN (proposed): the intra-tenant scope model
(workspaces), the generalized permission/role/grant RBAC (system and custom
roles, fine-grained permissions), teams, and scope-aware invitations. It is
docs-first by rule: nothing in Part II is built until this revision is reviewed.
The original design incorporated a security red-team pass (the isolation
boundary, the async consumer path, the bypass path, provisioning atomicity,
invitation and seat handling); Part II keeps the same posture, in particular
that the tenant boundary stays the only hard, database-enforced isolation layer.

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
conservative default the app tightens per endpoint). When the grant names no
target user, the session acts as the admin's own identity inside the tenant with
a read-only default: it can view but not mutate, and an endpoint must opt in to
allow a write under a target-less grant. The grant auto-expires at its absolute
cap with no rotation; ending it writes `ended_at` and emits `ImpersonationEnded`.

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

## Part II: workspaces, scoped RBAC, teams, and custom roles

Part I gives every tenant a flat membership with one of three roles. Real B2B
customers subdivide their own account: separate spaces for production, staging,
and development, or one space per internal team or project, each with its own
people and its own policies. Part II adds that as a first-class, optional layer
on top of Part I, without touching the tenant isolation boundary. The
load-bearing decision: a workspace is an authorization scope, not a second
isolation tier. The tenant stays the only hard, database-enforced boundary (RLS,
Part I); workspaces, teams, and custom roles are all resolved in the application
authorization layer, exactly as resource ownership and tenant role already are.

## 12. Workspaces: a scope inside the tenant

A **workspace** is a named scope within one tenant. A tenant has one or many;
the count and the names are the customer's, not ours (a company may run
`production` / `staging` / `dev`, or one workspace per team or per project). A
workspace never spans tenants.

`tenancy.workspaces`: `id`, `tenant_id`, `slug` (unique per tenant, citext),
`name`, `status` (`active` | `archived`), `created_at`, `created_by`. It is
tenant-owned, so it carries `tenant_id` and lives under the Part I tenant RLS
policy: listing workspaces is an ordinary tenant-scoped read, and one tenant can
never see another's workspaces. `workspace_id` is deliberately NOT a second RLS
GUC (see below).

**Resources may be workspace-scoped.** A tenant-owned table gains a nullable
`workspace_id`. NULL means a tenant-level row (visible to the whole tenant,
subject to role); a set value binds the row to that workspace. `Starter.Sample`
notes gain a nullable `workspace_id` as the worked example: a note may be created
at tenant level or inside a workspace, and the list endpoint can filter by
workspace.

**Why authorization scope, not a second RLS tier.** The tenant boundary is a
hard, cross-customer boundary: a leak is a breach, so it belongs in the database
(RLS). A workspace boundary is intra-customer: the same company, and its owners
and admins routinely need to read and act across every workspace (that is their
job). Three consequences make a second mandatory RLS GUC the wrong tool:

- The common admin query is "everything in my tenant, across all workspaces". A
  mandatory workspace GUC turns that into either many per-workspace queries or a
  bypass, and every new bypass path is a place isolation can go wrong.
- Workspace membership is fluid and fine-grained; RLS is coarse and
  per-connection. Modeling access as data (a `workspace_id` column plus scoped
  grants) fits how the access actually behaves.
- The industry splits it this way: cross-tenant isolation is physical (separate
  rows behind RLS, or separate accounts), while intra-account project or
  workspace access is authorization (GCP Org -> Folder -> Project IAM
  inheritance, GitHub Org -> Team -> Repo permissions, LaunchDarkly Project ->
  Environment). We match that.

So a workspace-owned row carries `workspace_id`, queries filter on it, and the
scoped-RBAC layer (section 13) refuses a caller with no grant in that workspace.
The tenant RLS still sits underneath as defense in depth: even a bug in workspace
authorization cannot leak another customer's data.

**Workspace context is per request, not in the token.** The access token still
carries only `tid` (Part I): a signed-in user works across many workspaces in one
session, so pinning the token to a workspace would be wrong. The workspace in
play is resolved per request from the route
(`/api/v1/workspaces/{workspaceId}/...` or the target resource's `workspace_id`),
and the caller's permission in that workspace is resolved per request, the same
stance Part I takes for roles.

**Silo escape hatch still applies.** A single workspace that needs
regulator-grade hard isolation (for example a `production` workspace holding
regulated data, separated from `dev`) uses the same per-tenant silo indirection
from section 10, keyed additionally on the workspace. Shared schema stays the
default; a siloed workspace is the documented exception, not a new mechanism.

## 13. Generalized RBAC: permissions, roles, and grants

Part I's fixed `owner > admin > member` is the degenerate case of a three-part
model that Part II makes explicit. The generalization is additive: Part I's
behavior is preserved exactly, with the fixed roles becoming the code-defined
system roles.

- **Permissions** are the application-defined, enumerated atoms of capability, a
  closed catalogue we ship. Customers compose them into roles; they never invent
  a permission (as in GitHub and Auth0 custom roles). Each is a stable string
  key, for example `members:read`, `members:manage`, `invitations:manage`,
  `workspaces:read`, `workspaces:manage`, `roles:manage`, `teams:manage`,
  `billing:manage`, `notes:read`, `notes:write`, `notes:delete`. A small set is
  reserved to owners and can never appear in a custom role: `tenant:manage`,
  `tenant:delete`, and ownership transfer.
- **Roles** are named permission sets. **System roles** (`owner`, `admin`,
  `member`) are defined in code, not stored as rows: they are the fixed
  permission sets `tenancy.memberships.role` (Part I) names, so they need no
  table and stay outside RLS entirely. **Custom roles** are per-tenant rows in
  `tenancy.roles` (`tenant_id` not null, tenant-owned, under the ordinary tenant
  RLS) with a tenant-chosen subset of the catalogue (section 15). A custom role
  records where it may be assigned (tenant scope, workspace scope, or both) and,
  when it is workspace-local, which workspace owns it.
- **Grants** (`tenancy.role_assignments`) bind a CUSTOM role to a principal at a
  scope: `(tenant_id, principal_type [user | team], principal_id, role_id,
  scope_type [tenant | workspace], scope_id)`. Only a custom role is grantable
  this way; a system role is conferred solely through `tenancy.memberships.role`
  (the tenant base role, applied tenant-wide), so cross-cutting system power is
  never handed out through a scoped grant. Assignments layer additional
  fine-grained, workspace-scoped, or team-held permissions on top of the base
  role. This is GitHub's shape exactly: an org base role plus repo- and
  team-specific permissions above it. Creating a grant validates that
  `scope_type` is one of the role's assignable scopes and, for a workspace-local
  role, that `scope_id` equals the role's owning workspace, so a role can never
  be bound wider than its author intended.

**"Roles" and "policies".** A role is a named set of permissions; a policy is a
grant, the binding of a role to a principal at a scope. That is role-based access
control (RBAC), the right default for B2B SaaS and what the large majority run
(GitHub, Slack, Linear). Rules that also depend on request attributes (time of
day, IP range, resource labels) are ABAC; they are a documented grow-into
(section 21) that plugs into this same per-request permission check, not a
day-one need. Start with roles and scoped grants; add conditions only when a
customer's compliance rule actually requires them.

**Effective permissions** for a caller at a scope (the tenant, or one workspace)
are the union of:

1. the permission set of the caller's tenant base role (`memberships.role`),
   which applies tenant-wide and therefore inherits into every workspace; plus
2. every `role_assignment` whose principal is the caller OR a team the caller
   belongs to (section 14), AND whose scope is the tenant (inherits to all
   workspaces) OR exactly the workspace in context.

Inheritance is downward only: a tenant-scope grant reaches every workspace; a
workspace-scope grant applies to that workspace alone and never confers
tenant-wide power. Resolution is per request and cached per request, fail-closed
(no matching grant means no permission), considers only an active membership (a
`suspended` membership confers nothing, so a suspension takes effect on the next
request), and reads `tenancy.*` under the tenant RLS of Part I.

**Gates.** `RequireTenantRole(minimum)` (Part I) stays for coarse system-role
checks and is unchanged. Part II adds `RequirePermission(permission)` and
`RequirePermission(permission, Scope.Workspace)` endpoint filters that resolve
effective permissions at the request's scope and return 403
`starter:permission-required` when it is absent. Resource ownership (the
`IAuthorizationService` layer, section 5) is unchanged and composes with
permissions exactly as tenant-admin does today: `notes:write` at workspace scope
plus the ownership handler yields "the owner, or anyone with write in this
workspace".

## 14. Teams

A **team** is a named group of users inside a tenant that can hold grants, so
access is managed for a group instead of user by user (GitHub teams).

- `tenancy.teams`: `id`, `tenant_id`, `slug` (unique per tenant), `name`,
  `created_at`, `created_by`. Tenant-owned, under RLS.
- `tenancy.team_members`: `id`, `tenant_id`, `team_id`, `user_id`, `created_at`.
  Unique `(team_id, user_id)`. Tenant-owned, under RLS.

A team is a principal in `role_assignments` (`principal_type = team`). The
effective-permission resolver (section 13) unions the grants of every team the
caller belongs to. Because resolution is per request, adding a user to a team
grants its permissions on their next request, and removing them revokes on the
next request, with no token churn. Team and membership management require
`teams:manage`.

## 15. Custom roles

**Who authors what.** The platform owns the permission catalogue and the system
roles; a tenant composes its own roles from that catalogue. This is the
industry-standard split (GitHub custom organization roles, Auth0 roles): the
application defines the vocabulary of permissions, the customer arranges them
into roles. So a tenant admin with `roles:manage` self-serves custom roles with
no platform operator in the loop, and the platform decides only what permissions
exist and, optionally, gates custom roles behind a plan tier (the entitlements
seam). The super-admin plane may additionally publish global role templates that
are seeded into every tenant (section 21).

A custom role is a name, an optional description, a chosen subset of the
permission catalogue, and where it may be assigned (tenant scope, workspace
scope, or both). It is stored as a `tenancy.roles` row (`tenant_id` not null,
tenant-owned) plus its `tenancy.role_permissions` rows (also tenant-owned).
System roles are not rows at all, so `tenancy.roles` holds only custom roles and
carries no null-tenant exception to the RLS boundary.

**Tenant-owned versus workspace-local roles.** A role's definition is owned at a
scope, recorded by `workspace_id` on the role row. A tenant-owned role
(`workspace_id` null) is visible across the tenant and assignable per its
`assignable_at`. A workspace-local role (`workspace_id` set) is defined by a
workspace admin with `roles:manage` in that workspace and is assignable only
there, so each workspace can carry its own roles without cluttering the rest.
This mirrors GCP, where a custom role can be defined at the organization or at a
single project. Tenant-owned roles cover most needs; reach for workspace-local
roles when one workspace needs a role the others should not see.

Guardrails:

- The catalogue is closed: a custom role can only contain permissions we ship,
  and never the owner-reserved ones (`tenant:manage`, `tenant:delete`, ownership
  transfer). Those stay system-role capabilities so cross-cutting control cannot
  be handed out piecemeal.
- A permission the tenant's plan does not include cannot be added (the
  entitlements seam, a grow-into from section 21; enforced as a no-op filter
  until billing exists).
- A workspace-local role's grants never reach tenant scope (no upward
  inheritance, section 13).
- Editing a custom role's permissions takes effect for every holder on their next
  request (per-request resolution).
- A custom role in use cannot be deleted; its assignments must be removed or
  reassigned first, so access never silently vanishes or dangles.

## 16. Scope-aware invitations

Part I invites a user to a tenant with a base role. Part II lets an invite also
target a workspace and a role there. `tenancy.invitations` gains
`workspace_id uuid null` and a nullable `role_id` (the scoped role to grant on
accept), alongside the existing base-role field. On accept, in the one bypass
transaction of section 8 (seat check under `SELECT ... FOR UPDATE`, email match,
single-use consume): the membership is created if the invitee is new to the
tenant (base role `member` unless the invite says otherwise), and, when the
invite carries `workspace_id` + `role_id`, the matching `role_assignment` is
created at that workspace scope. The invite's `role_id` must be a custom role
whose owning workspace is that same `workspace_id` (the section 13 grant
validation applies here too), so an invitation cannot bind a role wider than its
scope. So a person can be invited straight into "developer on the staging
workspace" in one step.

## 17. Data model additions (Part II)

All new tenant-owned tables carry `tenant_id` and live under the Part I tenant
RLS policy; nothing here adds a second GUC.

- `tenancy.workspaces` (section 12); `workspace_id` (nullable) added to
  `Starter.Sample` notes and to `tenancy.invitations`.
- `tenancy.roles` (custom roles only; system roles are code, not rows): `id`,
  `tenant_id` (not null), `key`, `name`, `description`, `assignable_at`
  (`tenant` | `workspace` | `both`), `workspace_id` (null for a tenant-owned
  role, set for a workspace-local one, section 15), `created_at`. Tenant-owned,
  under the ordinary tenant RLS. Unique on `(tenant_id, workspace_id, key)`, so a
  name is unique within its owning scope.
- `tenancy.role_permissions`: `role_id`, `tenant_id` (not null, denormalized from
  the owning role), `permission`. Tenant-owned and under RLS like every other
  tenant table, so a raw read cannot cross tenants; it holds custom-role rows
  only, since system-role permission sets live in code.
- `tenancy.role_assignments`: `id`, `tenant_id`, `principal_type`
  (`user` | `team`), `principal_id`, `role_id` (a custom role), `scope_type`
  (`tenant` | `workspace`), `scope_id` (null for tenant scope, else the
  `workspace_id`), `granted_by`, `created_at`. Tenant-owned, under RLS.
  Uniqueness is a partial unique index per scope kind (one
  `WHERE scope_type = 'tenant'` on `(tenant_id, principal_type, principal_id,
  role_id)`, one for workspace scope including `scope_id`), because a null
  `scope_id` would not collide under a plain unique constraint.
- `tenancy.teams`, `tenancy.team_members` (section 14).

`tenancy.memberships.role` (Part I) is unchanged and remains the tenant base
role. The permission catalogue and the system-role permission sets are code, not
tables: closed sets the application owns.

## 18. Tests for Part II (added to the crown-jewel suite)

- **Custom role.** A custom role granting only `invitations:manage` lets its
  holder invite members but not manage them; editing the role's permissions
  changes what its holder can do on the next request.
- **Guardrails.** Creating or editing a custom role that contains an
  owner-reserved permission (`tenant:manage`, `tenant:delete`, ownership
  transfer) is rejected; assigning a workspace-local role at tenant scope, or at
  a different workspace, is rejected (the section 13 scope validation).
- **Scoped RBAC and inheritance.** A tenant-scope grant is honored in every
  workspace; a workspace-scope grant is honored only in that workspace and
  confers nothing tenant-wide (no upward inheritance: a workspace admin cannot
  administer the tenant).
- **Workspace isolation within a tenant.** A workspace-scoped note in workspace A
  does not appear when listing workspace B of the same tenant; a tenant admin
  sees across both; a caller from another tenant still gets 404 by RLS, proving
  the tenant boundary is untouched.
- **Teams.** A grant held by a team confers its permissions to a member; removing
  the member from the team revokes them on the next request.
- **Scope-aware invitation.** Accepting a workspace-scoped invite creates the
  membership and the workspace `role_assignment` in one transaction, and two
  concurrent accepts still cannot exceed `seat_limit`.

## 19. Build sequence (increments 5-7)

Part II is built on top of the shipped Part I, in the same reviewable-increment
discipline (each a `/review-gate`, a blocking-reviewer pass, and a
`/pre-merge-gate`):

5. **Scoped-RBAC engine and custom roles, tenant scope first.** The permission
   catalogue, `roles` + `role_permissions` (system roles seeded, custom roles
   tenant-defined), `role_assignments` (user principal, tenant scope), the
   effective-permission resolver, the `RequirePermission` gate, and the
   custom-role CRUD and assignment API. Behavior-preserving over increments 1-4:
   the system roles reproduce the existing `owner > admin > member` permissions.
6. **Workspaces as a scope.** The `workspaces` table and its CRUD, `workspace_id`
   on Sample notes, `role_assignments` and the resolver and gate extended to
   workspace scope, and workspace context resolved from the route.
7. **Teams and scope-aware invitations.** `teams` + `team_members`, team
   principals in `role_assignments`, team CRUD and membership, and invitations
   extended with `workspace_id` + `role_id`.

The SaaS layer stays deletable (section 10): removing `Starter.Tenancy` and the
Platform tenant pieces drops Part II with it.

## 20. Lifecycle: onboarding and offboarding

Every entity in the control plane has an onboarding and an offboarding path, and
the offboarding path is the one teams forget. The starter provides the
control-plane APIs for these workflows; the tenant-admin portal and the platform
super-admin portal are frontend UI built over those APIs.

- **Tenant.** Onboard by self-serve signup or an invited owner (section 8).
  Offboard as a state machine: `active -> suspended -> deleted` (soft delete,
  Part I), then a retention window, then a hard delete that also produces a data
  export (the data-portability and erasure path, section 21). Suspending stops
  new access at once; existing short tokens age out within the access window.
- **Workspace.** Onboard by create (section 12). Offboard by archive
  (`active -> archived`): its resources become read-only (workspace-scoped writes
  are refused with a stable problem) and no new resources or grants can be created
  in it, while reads still work; nothing is destroyed, so unarchive restores it.
- **Team.** Onboard by create, then add and remove members. Offboard by delete,
  which first removes the team's `role_assignments` so no dangling grant survives.
- **Person (membership).** Onboard by invite and accept, or as a self-serve
  owner. Offboard by remove or suspend, which revokes the member's
  `role_assignments` and team memberships on the next request. Resources the
  person owned are reassigned or transferred, never silently orphaned: a tenant
  admin can already manage any resource (section 5, layer 3). Enterprise
  deprovisioning (SCIM) drives this same offboarding path from the customer's
  directory (section 21).
- **Role and policy.** Onboard by defining a custom role and granting it
  (sections 13, 15). Offboard by revoking grants and deleting the role; a role in
  use cannot be deleted until its assignments are removed or reassigned, so
  access never dangles.

Two rules cut across all of them: an offboarding action revokes access on the
next request (per-request resolution, never waiting for a token to expire), and
it is recorded on the event spine (who offboarded what, and when), because
offboarding is exactly what an incident review reconstructs.

## 21. Beyond this blueprint: the SaaS grow-into surface

The tenancy layer plus the existing spine (outbox, idempotency, sessions, problem
details, rate limiting) already carries the hooks for the rest of the
control-plane surface a typical B2B SaaS grows into. These are deliberately not
built here; each is noted so it hangs off the existing mechanisms rather than a
rewrite:

- **API keys, service accounts, PATs**: a non-human principal type, hashed like
  the one-time tokens, carrying scoped grants (section 13) instead of a session.
  DESIGNED and being built out - see [service-accounts.md](service-accounts.md).
- **SSO (SAML / OIDC) and SCIM provisioning**: a per-tenant identity-provider
  config; SCIM maps directory groups to teams (section 14) and roles.
- **MFA / TOTP**: an Identity add-on on the sign-in path; no tenancy change.
- **Billing (plans, subscriptions, seats, metering) and entitlements**: `plan`
  and `seat_limit` already exist on the tenant; entitlements gate the permission
  catalogue (section 15) and features per plan. DESIGNED and being built out -
  see [billing-and-entitlements.md](billing-and-entitlements.md).
- **A first-class, queryable audit log**: distinct from `domain_events`; a
  projection built by a consumer off the outbox (the impersonation grant is the
  first audited action). DESIGNED and being built out - see
  [audit-log.md](audit-log.md).
- **Outbound webhooks**: a consumer that fans domain events out to
  tenant-registered endpoints, reusing the at-least-once delivery the outbox
  gives. DESIGNED and being built out - see [webhooks.md](webhooks.md).
- **Data export and account deletion (GDPR / DSAR)**: tenant-scoped reads and a
  soft-delete-to-hard-delete lifecycle on top of the existing tenant `status`.
- **In-app notifications, usage quotas, data residency**: notifications ride the
  existing `IEmailSender` and consumer pattern; quotas ride the rate limiter;
  residency rides the silo indirection (section 12).
- **Global role templates and platform policy defaults**: the super-admin plane
  authors role templates seeded into every tenant, plus platform-wide defaults
  (password, session, and lockout policy) a tenant inherits and may tighten.
- **A policy engine (ABAC)**: conditional grants (time, IP, resource attributes)
  through an engine such as Cedar or Open Policy Agent, evaluated at the same
  per-request permission check (section 13). RBAC stays the default; ABAC layers
  on only when a customer's rule needs a condition.
