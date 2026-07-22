# The audit log

Status: DESIGN (proposed). This is the first of the SaaS grow-into features
(multi-tenancy.md section 21) to be built out. It is docs-first by rule: nothing
here is built until this revision is reviewed. It builds directly on the event
spine and outbox already shipped in Part I, and on the platform super-admin
plane; read multi-tenancy.md sections 3 (the outbox / consumer path), 6 (data
model), and 7 (the super-admin plane and impersonation) first.

## 1. The decision, up front

- **The audit log is a queryable projection built off the outbox, not a new
  write path.** Every module already emits domain events into the append-only
  event spine (`platform.domain_events`) and, when a consumer is registered, into
  the outbox. The audit log is a Fast-lane `IDomainEventConsumer` that projects
  those events into a table shaped for the two questions an audit log answers:
  "who did what, to what, and when, in my tenant" and, for the platform operator,
  "what did my staff do across tenants". This is the industry-standard shape:
  Stripe, GitHub, and AWS (CloudTrail) all expose the audit trail as a queryable
  projection distinct from the raw event stream, with the raw stream retained
  underneath.
- **Two scopes, because there are genuinely two audiences.** A TENANT audit log
  records actions inside one tenant and is readable by that tenant's admins (and,
  cross-tenant, by the platform operator) - this mirrors a GitHub organization's
  audit log. A PLATFORM audit log records platform-staff actions that are not
  scoped to any one tenant (granting or revoking a super-admin) and is readable
  only by the platform operator - this mirrors GitHub's enterprise audit log or
  an AWS organization trail. Keeping them separate is not extra work for its own
  sake: they have different readers, different isolation, and different retention.
- **The tenant audit log is tenant-owned and RLS-enforced, exactly like every
  other tenant table.** It carries a `tenant_id` and `FORCE ROW LEVEL SECURITY`,
  so a tenant admin reading their audit log is bound by the same authoritative
  boundary as every other read. This makes `platform.audit_log` the FIRST
  RLS-bearing table in the `platform` schema; the placement is deliberate (see
  section 9) and the one-line "platform tables are not tenant-owned" note in
  `PlatformDbContext` is updated to name the exception.
- **The impersonation grant is the first audited action, end to end.** It already
  emits `platform.impersonation.started` / `.ended` stamped with the target
  tenant (multi-tenancy.md section 7), so the moment the consumer ships, an
  operator impersonating a user lands a row in that tenant's audit log with no
  further wiring. That was the point of emitting the event in Part I.
- **Append-only, integrity over convenience.** Audit rows are inserted, never
  updated or deleted by the application. The natural primary key is the source
  domain event's id, which makes the projection idempotent under the outbox's
  at-least-once delivery for free (a redelivery is a primary-key no-op, not a
  duplicate row). Retention and purge are an operator concern (section 8), run on
  the bypass path, never an application mutation.

## 2. What is audited, and on which path

Audit entries come from two paths, matching the two scopes.

**Tenant scope (asynchronous projection off the outbox).** A Fast-lane consumer,
`AuditProjectionConsumer`, subscribes to the tenant-scoped event catalogue: every
event that carries a `tenant_id`. That is all `tenancy.*` control-plane events
(tenant created, membership created / role changed / removed, invitation created
/ revoked, settings updated, ownership transferred, workspace and team and role
and role-assignment lifecycle), the tenant-scoped `platform.impersonation.*`
events (they carry the target tenant), and the sample module's `sample.note.*`.
The dispatcher binds each delivery's DB scope to `event.TenantId`, so the
consumer inserts under that tenant's GUC and RLS stamps the row to exactly one
tenant. No bypass, no cross-tenant write; the consumer follows the
`NoteIndexConsumer` shape precisely.

**Platform scope (synchronous, transactional at the action site).** The two
null-tenant platform-admin actions - `platform.admin.granted` and
`platform.admin.revoked` - are NOT projected by the consumer. A null-tenant event
would leave the consumer's GUC unset, and an insert into the FORCE-RLS tenant
table would (correctly) fail the `WITH CHECK` and eventually poison. Instead these
two actions write a `platform.platform_audit_log` row (no RLS) in the SAME bypass
transaction that grants or revokes the admin, inside `PlatformAdminService` (which
is already on the bypass allowlist and already transactional). Writing the audit
row transactionally with the action it records is strictly stronger than an
eventual projection for the highest-sensitivity actions in the system.

Two constraints make this correct rather than merely convenient. First, the audit
write sits INSIDE the same guard that emits the domain event: `GrantPlatformAdmin`
only mutates and emits when the insert actually took effect (`inserted == 1`; a
repeat grant of an existing admin is a no-op that emits nothing), and the audit
row is written only on that same branch, with its primary key equal to the emitted
event's id. So there is never an audit row without a real action behind it, and
never a duplicate. Revoke's early-return guards already commit nothing on the
no-op paths, so the same rule holds. Second, `PlatformAdminService` lives in the
Tenancy module and cannot see the internal `PlatformDbContext`, so it does not
hand-roll the insert: it calls a Platform-registered `IPlatformAuditWriter`,
passing the open connection and transaction, and Platform owns the column list in
one place (section 4).

Identity events (`identity.user.registered`, `.session.created`, and so on) are
deliberately NOT audited here. They are user-activity signals retained on the
event spine; a security-events / login-history feature is a separate, later
concern and would project them into its own table. Folding raw sign-in traffic
into the admin audit log is below the bar (it is noise that hides the
administrative actions an auditor is actually looking for).

## 3. The tenant audit log

`platform.audit_log`, tenant-owned, RLS-enforced (`ITenantOwned`, `enable` +
`force row level security`, the standard `tenant_isolation` policy keyed on
`app.current_tenant`). One row per audited domain event.

| column | type | notes |
|---|---|---|
| `id` | uuid | PK; equals the source domain event id (idempotent projection) |
| `tenant_id` | uuid not null | RLS discriminator; stamped from the event |
| `occurred_at` | timestamptz not null | the event's `occurred_at` (when the action happened) |
| `recorded_at` | timestamptz not null | when the projection wrote the row (`Clock.UtcNow`) |
| `action` | text not null | the event type, e.g. `tenancy.member.role_changed` |
| `actor_user_id` | uuid null | the event's `actor_user_id` (null for system actions) |
| `entity_id` | uuid null | the event's primary subject id |
| `summary` | text not null | a short, human-readable rendering of the action |
| `data` | jsonb not null | the event payload verbatim: ids and scalars only, never PII |

Indexes: `(tenant_id, occurred_at desc)` for the default reverse-chronological
feed and keyset pagination; `(tenant_id, actor_user_id, occurred_at desc)` and
`(tenant_id, action, occurred_at desc)` for the two common filters. `data` is the
event payload unchanged, so the audit log inherits the spine's "ids and scalars,
never PII" discipline; `summary` is a bounded, non-PII sentence built from the
action and the ids.

There is deliberately NO `workspace_id` column. No domain event today carries a
workspace id in its payload (workspace lifecycle events put it in `entity_id`;
workspace-scoped role grants drop the scope id from the payload entirely), so a
`workspace_id` column would be permanently null and advertise a filter that does
not work. Workspace-scoped audit filtering is a documented extension: it requires
first enriching the relevant event payloads with their workspace id, then adding
the column and index. For workspace lifecycle actions, `entity_id` already holds
the workspace id.

## 4. The platform audit log

`platform.platform_audit_log`, NOT tenant-owned, no RLS - consistent with every
other platform table. Readable only through the super-admin plane. One row per
platform-staff action not scoped to a tenant.

| column | type | notes |
|---|---|---|
| `id` | uuid | PK; equals the source domain event id |
| `occurred_at` | timestamptz not null | when the action happened |
| `recorded_at` | timestamptz not null | when the row was written |
| `action` | text not null | e.g. `platform.admin.granted` |
| `actor_user_id` | uuid null | the platform staff member who acted |
| `subject_user_id` | uuid null | the user the action was about |
| `summary` | text not null | short human-readable rendering |
| `data` | jsonb not null | ids and scalars only |

Because this table is written only on the bypass path from an allowlisted
control-plane type, and read only behind `RequirePlatformAdmin`, it never needs a
`tenant_id`. The write goes through a Platform-registered `IPlatformAuditWriter`
(a parameterized insert taking the caller's open connection and transaction), so
the column list lives once in Platform even though the call site is in the Tenancy
control plane; the super-admin read uses the `PlatformAuditLogRow` EF mapping in
`PlatformDbContext`.

## 5. The projection consumer

`AuditProjectionConsumer` is a Platform `IDomainEventConsumer`, Fast lane,
registered as a singleton in the platform composition. It resolves a
request-style (RLS-bound) `PlatformDbContext` from the passed `IServiceProvider`
scope, never `BypassDataSource`. Platform is not constrained by the
bypass-containment arch tests (it owns the mechanism), so this abstention is
code-review discipline, held to deliberately: the projection is a tenant-scoped
write and must never reach across tenants. For each delivery:

1. The dispatcher has already bound the scope to `event.TenantId` and opened the
   tenant GUC. The consumer maps the `DomainEventRecord` to an `AuditLogRow`
   (`id = event.Id`, tenant/actor/occurred-at/action/payload copied, `summary`
   rendered). Because Platform cannot reference module payload types
   (`DependencyShapeTests` forbids it), the payload is read by untyped JSON
   traversal (`JsonDocument`), never typed deserialization; `summary` is composed
   from the action and a few well-known scalar fields, tolerating their absence.
2. It inserts the row. RLS stamps and confirms `tenant_id`. A redelivery hits the
   `id` primary key and is caught as a unique violation, which the consumer
   treats as success (the row is already there) - idempotent by construction,
   the correct dedup shape for an audit write (the notification consumer's
   best-effort `ProcessedEventStore` path is explicitly the wrong tool here,
   because a claim that commits separately from the write can drop the record).

The consumer is registered AFTER the events it subscribes to already exist, so
the enqueue-time routing in `OutboxWriter` starts writing Fast-lane outbox rows
for those event types from the moment it ships. Events emitted before the
consumer existed have their spine rows but were never enqueued for audit; this is
expected and documented (the audit log begins when it is turned on, and history
before that lives on the immutable spine).

## 6. Reading the audit log

**Tenant-admin query** - `GET /api/v1/tenant/audit`, on the tenant group
(`RequireTenant().RequireAuthorization()`), gated by `RequirePermission(audit:read)`.
RLS scopes results to the caller's tenant automatically; there is no `tenant_id`
in the request. Filters: `actor` (user id), `action` (exact or dotted prefix,
e.g. `tenancy.member.` matches all membership actions), `entity`, `from` / `to`
(time range), and keyset pagination (`before` cursor on `(occurred_at, id)`), the
same pagination contract the other list endpoints use. The query is served by a
Platform-registered `IAuditQuery` reading the RLS-bound context.

**Super-admin query** - `GET /api/v1/platform/audit`, on the platform group
behind `RequirePlatformAdmin`. Reads on the bypass path (a Platform reader type,
which Platform may legitimately use), so it can cross tenants. A `tenant` filter
narrows to one tenant; omitting it returns entries across all tenants (the
compliance view). A `scope=platform` selector returns the platform audit log
(section 4) instead of the tenant projection. Everything the super-admin reads
here is itself an operator action, but reads are not re-audited (auditing reads
of the audit log is a documented, off-by-default extension; turning it on is a
retention and volume decision, not a correctness one).

## 7. Permissions

One new permission atom, `audit:read`, added to the closed catalogue
(`Permissions.All`) and to the `AdminSet` in `SystemRolePermissions` (so tenant
Admins and Owners can read their audit log; Members cannot). It is grantable in a
custom role like any other non-owner-reserved permission, so a tenant can mint a
read-only "Auditor" role. Super-admin audit access is orthogonal: it is gated by
`RequirePlatformAdmin` (membership of `platform.platform_admins`), never by a
tenant permission.

## 8. Retention, integrity, and purge

- **Append-only, enforced at the database, not just in code.** The request role
  (`starter_app`) is granted only `select, insert` on `platform.audit_log` and
  nothing at all on `platform.platform_audit_log`. This is NOT automatic: the boot
  -time role provisioner issues a blanket `grant select, insert, update, delete on
  all tables` per schema, so the audit tables need a targeted REVOKE pass, run in
  the same provisioner step, every boot (idempotent), AFTER the blanket grant so
  it is never silently undone: `revoke update, delete on platform.audit_log from
  starter_app` and `revoke all on platform.platform_audit_log from starter_app`.
  With that in place, an attacker who reaches request-role SQL (an injection, a
  forgotten filter) still cannot edit or erase the tenant audit trail, and cannot
  see or forge the platform audit trail at all. The bypass role (the migrating
  owner) retains full DML for retention and reads. Without the REVOKE the log is
  only app-discipline append-only, which is below the bar for an audit log; the
  REVOKE is part of this increment's build sequence, not an optional hardening.
- **Retention is an operator job on the bypass path.** A retention window (default
  documented, for example 400 days for the tenant log) is enforced by a purge run
  as the bypass role, the only principal that may delete audit rows, and that
  purge is itself recorded in the platform audit log. Per-tenant retention
  overrides ride the entitlements work (billing increment): a higher plan buys a
  longer window.
- **Tamper-evidence is a documented grow-into, not built here.** For customers who
  need cryptographic non-repudiation, the append-only table is the hook for a
  hash-chain (each row carries the hash of the previous row for its tenant) or
  periodic anchoring to an external notary. RLS + append-only + bypass-only delete
  is the correct MVP bar; the hash-chain layers on without a schema rewrite.

## 9. Placement and deletability

The audit log lives in `Starter.Platform` next to the outbox it projects from,
not in a new module and not in a business module. It is a cross-cutting spine
concern: it consumes every module's events through the event envelope (a string
`event_type` plus a payload), so it references no module, and it needs the same
cross-tenant read privilege the control plane already has. A business-module
placement would have to invent a second bypass-allowlist mechanism for that
module to serve the super-admin view; the Platform placement needs none, because
Platform legitimately owns `BypassDataSource`.

The cost is that `platform.audit_log` is the first RLS table in the `platform`
schema. That is a deliberate, documented exception, not a drift: the tenant audit
log must be bound by the authoritative boundary like every other tenant read, and
RLS is that boundary. The `PlatformDbContext` class note is updated from "platform
tables are not tenant-owned (no RLS)" to name the audit log as the single
tenant-owned, RLS-enforced platform table.

Deletability: the feature is removable by dropping the two tables, the consumer
registration, the two endpoint groups, and the `audit:read` atom, leaving the
event spine (the source of truth) untouched.

## 10. Tests (added to the crown-jewel suite)

- **Isolation**: a tenant admin reading `/api/v1/tenant/audit` sees only their own
  tenant's rows; a second tenant's actions never appear. This is the same RLS
  isolation assertion the other tenant tables carry, applied to the audit log.
- **The projection is real and idempotent**: an action (create a note, change a
  member's role) produces exactly one audit row for the source event id; a forced
  redelivery of the same event produces no second row.
- **Impersonation is audited end to end**: an operator impersonation start lands a
  `platform.impersonation.started` row in the TARGET tenant's audit log, visible
  to that tenant's admin, with the operator as actor.
- **Platform actions are audited transactionally**: granting a super-admin writes a
  `platform.platform_audit_log` row in the same transaction; a rolled-back grant
  leaves no audit row.
- **Permission gate**: a Member (no `audit:read`) gets 403 on the tenant audit
  endpoint; an Admin succeeds; a custom "Auditor" role with only `audit:read`
  succeeds for reads and 403s on everything else.
- **Super-admin cross-tenant read**: a platform admin reads across tenants and,
  with a `tenant` filter, narrows to one; a non-admin gets 403.
- **PII discipline**: an arch/convention test (or a focused unit test) asserts the
  projected `data` is the event payload verbatim, so the "ids and scalars, never
  PII" rule the spine already enforces is inherited, not re-violated.
- **Catalogue completeness**: a reflection test collects every event-type string
  constant across the modules and asserts each is EITHER in
  `AuditProjectionConsumer.EventTypes` OR in an explicit, named "not audited" set
  (the identity user-activity events and the null-tenant `platform.admin.*`
  events, which are audited synchronously). A new event type then fails the build
  until someone categorizes it, closing the "silently unaudited" gap (an
  unsubscribed event never even gets a Fast-lane outbox row).
- **Append-only is DB-enforced**: after boot provisioning, an attempt to `update`
  or `delete` a `platform.audit_log` row as the request role is rejected by
  Postgres (not merely by the absence of an API), and the request role cannot read
  `platform.platform_audit_log` at all.

## 11. Build sequence (this increment)

1. Migration: `platform.audit_log` (RLS: `ITenantOwned`, enable + force RLS, the
   standard `tenant_isolation` policy) + `platform.platform_audit_log` (no RLS),
   plus the indexes in section 3.
2. Provisioner: extend the boot-time role step to run, after the blanket schema
   grant, the targeted REVOKE pass from section 8 (`revoke update, delete on
   platform.audit_log`; `revoke all on platform.platform_audit_log`; both from the
   request role), so the DB-enforced append-only / bypass-only posture survives
   every boot.
3. `AuditLogRow` / `PlatformAuditLogRow` entities mapped in `PlatformDbContext`;
   the "platform tables are not tenant-owned" class note updated to name
   `audit_log` as the single RLS-enforced exception.
4. `AuditProjectionConsumer` (Fast lane, untyped-JSON payload read) + singleton
   registration in the platform composition. Its `EventTypes` lists the
   tenant-scoped catalogue; no change to `TenancyEvents` is needed for this
   increment.
5. `IPlatformAuditWriter` (Platform, parameterized insert on a passed
   connection/transaction) + the call added to `PlatformAdminService`'s grant and
   revoke, inside the same guard that emits the domain event, PK = event id.
6. `IAuditQuery` (RLS read, request context) + `IAuditAdminQuery` (bypass read)
   Platform services; keyset pagination reusing the existing list contract.
7. Endpoints: tenant `GET /api/v1/tenant/audit` (`RequirePermission(audit:read)`);
   platform `GET /api/v1/platform/audit` (`RequirePlatformAdmin`, `tenant` and
   `scope=platform` selectors).
8. `audit:read` added to `Permissions.All` and `AdminSet`.
9. Tests (section 10) added to the integration suite, including the catalogue
   -completeness reflection test and the DB-enforced-append-only test.
