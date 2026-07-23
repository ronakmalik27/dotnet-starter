# Data export and erasure (GDPR / DSAR)

Status: DESIGN (proposed). The seventh SaaS grow-into feature (multi-tenancy.md
section 21, "Data export and account deletion (GDPR / DSAR)"). Docs-first: nothing
here is built until this revision is reviewed. It implements the committed
offboarding path from multi-tenancy.md section 20: `active -> suspended -> deleted`
(soft, already built) then a retention window then a hard delete that also produces
a data export.

## 1. The decision, up front

- **Two distinct rights, two distinct mechanisms.** Data EXPORT (GDPR Art. 15/20,
  access and portability) is a tenant-scoped READ that assembles the tenant's data
  into a machine-readable bundle. Data ERASURE (Art. 17, right to be forgotten) is
  a hard DELETE of the tenant's rows. They share nothing mechanically and are gated
  differently (a tenant admin self-serves an export; only a super-admin erases).
- **The offboarding lifecycle is a state machine, and the hard delete is the only
  new state transition.** `active -> suspended -> deleted` (soft, status-only) is
  already built (Part I: super-admin and owner both soft-delete; the row is never
  hard-deleted, only `status = deleted`). This increment adds: a `deleted_at`
  stamp, a RETENTION WINDOW after soft-delete, and the HARD DELETE that purges the
  tenant's rows once the window elapses. A soft-deleted tenant is recoverable
  (reactivate); a hard-deleted tenant is gone.
- **The hard delete PRODUCES a final export before it purges.** Per the committed
  path, erasure is preceded by a portability snapshot: the operator captures
  everything about to be destroyed (the compliance record, and the customer's last
  chance at their data). The self-serve export is the tenant-facing portability
  artifact; the hard-delete snapshot is the operator's pre-purge record.
- **Export runs on the REQUEST path under RLS; erasure runs on the BYPASS path.
  This split is forced by the isolation model and the arch tests, and it drives the
  whole design.** A self-serve export reads only the caller's OWN tenant, so RLS is
  exactly the right boundary and no control-plane privilege is needed. A hard delete
  is a cross-tenant super-admin act on a target tenant, so it needs the bypass role
  (BYPASSRLS). The arch tests forbid `BypassDataSource` in the `Sample` and
  `Identity` modules and the Api layer (only Platform is unconstrained; Tenancy has
  a narrow allowlist), so erasure CANNOT be a per-module bypass operation. Instead
  each module DECLARES its tenant-owned tables and a Platform-hosted executor issues
  the deletes on bypass. Modules stay bypass-free; Platform, which legitimately owns
  the cross-tenant control plane, does the privileged work.
- **Erasure safety is an explicit `where tenant_id = @tenantId` on every statement,
  not RLS.** The bypass role ignores RLS (that is the point of BYPASSRLS), so RLS
  does NOT scope an erasure delete. A missing `where` would purge every tenant. So
  every erasure statement carries an explicit, parameterized tenant filter, and a
  test proves erasing tenant A leaves tenant B's rows intact in every table. This is
  the single most dangerous operation in the whole starter; it is treated that way.

## 2. The offboarding state machine and retention

- States (unchanged vocabulary): `active`, `suspended`, `deleted`. Soft-delete sets
  `status = deleted`. This increment adds a nullable `deleted_at timestamptz` to
  `tenancy.tenants`, stamped when status becomes `deleted` (both the super-admin
  `DeleteTenantAsync` and the owner `SoftDeleteTenantAsync` paths), and cleared
  (set null) on reactivate.
- The RETENTION WINDOW is `DsarOptions.RetentionDays` (default 30), a validated,
  bound-on-start option. A hard delete is permitted only when
  `deleted_at + RetentionDays <= now` (comparing against `Clock.UtcNow`, never
  `DateTime.UtcNow` - the banned-API arch test forbids it, and the injected clock
  is what lets a test cross the window), OR when the super-admin passes an explicit
  `{ "force": true }` (a documented break-glass for a legal erasure demand that
  cannot wait out the window). A tenant that is not `deleted` cannot be hard-deleted
  (409): erasure follows soft-delete, never skips it.
- **Reactivate must be EXTENDED to make soft-delete recoverable (a new code
  change, NOT already present).** Today `ReactivateTenantAsync` accepts only
  `suspended -> active` (a `deleted` source is a Conflict), so a soft-deleted
  tenant currently has no way back - which contradicts the whole point of a
  retention window. This increment widens the allowed source state to include
  `deleted` (so `deleted -> active` and `suspended -> active` both reactivate) and
  clears `deleted_at` on the transition. That is the standard "restore within N
  days" model (GitHub, Google Workspace). A HARD-deleted tenant cannot be
  reactivated - its rows are gone.

## 3. Data export (Art. 15/20), request path, RLS

- `IDataExportContributor` (a Platform port): each module contributes one or more
  named sections of the ACTIVE tenant's data, read through its OWN request-scoped,
  RLS-bound context. No bypass anywhere, so `Sample` and every other module
  implement it without touching a control-plane privilege.

  ```
  string Section { get; }                                  // e.g. "workspaces"
  Task<object?> ExportAsync(CancellationToken ct);         // the section's rows, shaped
  ```

- `ITenantExportService` (Platform) resolves `IEnumerable<IDataExportContributor>`,
  invokes each, and assembles the bundle:

  ```json
  {
    "formatVersion": 1,
    "tenantId": "<uuid>",
    "generatedAt": "<iso-8601>",
    "sections": { "tenant": { ... }, "memberships": [ ... ], "workspaces": [ ... ] }
  }
  ```

- **Secrets are EXCLUDED from the export by each contributor.** The bundle is the
  tenant's own data, but a credential artifact is not "data the subject is entitled
  to a copy of" and must never leave the system in a portable file. Concretely: the
  service-account section omits `key_hash`; the webhook-endpoint section omits the
  encrypted signing secret. Everything else (memberships, roles, workspaces, teams,
  invitations, notes, audit log, usage counters, flag overrides) is included. This
  is a per-contributor obligation, called out in each contributor and in section 8.
- Contributors by module: TENANCY - tenant profile, memberships, workspaces, teams
  + team members, custom roles + role permissions, role assignments, invitations,
  service accounts (no `key_hash`). SAMPLE - notes. PLATFORM - audit log, webhook
  endpoints (no secret) + deliveries, usage counters, feature-flag overrides.
- Endpoint: `GET /api/v1/tenant/export`, gated `RequirePermission(data:export)` (a
  new atom, in the owner+admin system-role set - a bulk export of all tenant data is
  an administrative act, not a routine read). The atom is ALSO added to
  `Permissions.NotServiceAccountGrantable` (alongside `roles:manage` /
  `api-keys:manage`): a bulk-exfiltration primitive on an unattended, always-on
  service-account key is a distinct risk class from self-escalation, and a leaked
  key that can pull the entire tenant data set in one call is exactly what to
  refuse. So `data:export` is a human-admin capability only, never grantable to a
  service account. Returns the bundle as JSON. It emits
  `tenancy.tenant.data_exported` (added to `DeliverableEvents.TenantScoped`, so a
  bulk data access is AUDITED and webhook-deliverable; the `CatalogueCompleteness`
  test fails the build until it is registered) - the actor and a section-count
  summary, no payload copy.
- Synchronous assembly is fine for a starter (a tenant's data is small). Large-tenant
  async export to an object-store artifact with a signed download URL is a documented
  grow-into (section 9); the contributor seam does not change.

## 4. Data erasure (Art. 17), bypass path, Platform-executed

- `ITenantErasureContributor` (a Platform port): each module DECLARES its
  tenant-owned tables, schema-qualified, in FK-safe delete order (children before
  parents), each with the column that carries the tenant id. NO module touches
  bypass; declaration only.

  ```
  // (schemaQualifiedTable, tenantKeyColumn) pairs, in delete order.
  IReadOnlyList<TenantTable> Tables { get; }   // TenantTable(string Table, string KeyColumn)
  ```

  Nearly every table keys on `tenant_id`; the sole exception is `tenancy.tenants`
  itself, whose OWN `id` is the discriminator (there is no `tenant_id` column), so
  its pair is `("tenancy.tenants", "id")` and it is declared LAST.
- `ITenantErasureService` (Platform, bypass) purges a target tenant: open ONE bypass
  transaction, and for every declared table across every module (Platform's own
  tables included), execute `delete from {table} where {keyColumn} = @tenantId` with
  a parameterized tenant id. The table and column names come only from the trusted
  code-side declarations (never client input), so the interpolation into SQL is safe;
  the tenant id is always a bound parameter. Commit once.
- Tables to erase: the full `ITenantOwned` set - TENANCY (schema `tenancy`):
  `role_assignments`, `role_permissions`, `team_members`, `teams`, `roles` (the
  custom-role table is named `roles`, NOT `custom_roles`), `invitations`,
  `service_accounts`, `memberships`, `workspaces`, then `tenants` LAST (its own `id`
  is the key column); SAMPLE (schema `sample`): `note_index`, `notes`; PLATFORM
  (schema `platform`): `audit_log`, `webhook_deliveries`, `webhook_endpoints`,
  `usage_counters`, `feature_flag_overrides`, plus the tenant's rows on the event
  spine (`domain_events`, and any pending `outbox`) since those carry tenant
  payloads. `platform_audit_log` is NOT tenant-owned (operator actions, retained
  under legal basis) and is never touched by erasure - it is where the erasure
  records ITSELF (section 6).
- **Index the event-spine tenant columns FIRST (a migration in this increment).**
  `domain_events.tenant_id` and `outbox.tenant_id` were added without an index, and
  `domain_events` is monthly-partitioned and kept forever. A `delete .. where
  tenant_id = @t` over them would sequentially scan an ever-growing table inside the
  single bypass transaction that also holds locks on 16+ other tables, contending
  with the live dispatcher and getting slower every month. Add
  `create index ix_domain_events_tenant_id on platform.domain_events (tenant_id)`
  (propagates to every partition via the parent) and `ix_outbox_tenant_id on
  platform.outbox (tenant_id)`. (In this starter the migration runs on empty tables,
  so a plain `CREATE INDEX` is fine; on a populated production table use
  `CREATE INDEX CONCURRENTLY` out of band - an ops note.)
- **Revoke the tenant's live sessions (defense-in-depth).** `identity.sessions` is
  NOT `ITenantOwned` (sessions belong to the global Identity user) but carries a
  `tenant_id` set on tenant-select/refresh, so an erased tenant is still referenced
  by any unexpired session until it ages out. As part of the same bypass transaction
  the erasure service runs `update identity.sessions set revoked_at = now() where
  tenant_id = @tenantId and revoked_at is null`, killing any live token for the
  tenant immediately rather than waiting out its natural expiry. The blast radius of
  NOT doing this is bounded (RLS still isolates every other tenant, and the erased
  tenant's own tables are now empty, so a stale `tid` claim resolves to nothing), so
  this is defense-in-depth, not a correctness fix; the revoked rows themselves are
  retained (session audit history) and are cheap non-PII references.
- `platform.processed_events` (the consumer dedup claims) has no `tenant_id` and no
  FK to the spine, so purging a tenant's `domain_events` leaves its `(consumer,
  event_id)` claim rows orphaned. This is harmless: the rows carry a consumer name,
  an event id, and a timestamp (no PII), and no FK can be violated. Left in place
  (documented), not swept.
- The append-only guarantee (audit_log has UPDATE/DELETE revoked from the REQUEST
  role) is not violated: the bypass role, which owns the tables, performs the
  erasure, exactly as it performs migrations. Append-only binds the request path,
  not the control plane doing a lawful erasure.
- Cross-contributor ordering is NOT guaranteed FK-safe by construction (the
  aggregate order across `IEnumerable<ITenantErasureContributor>` follows DI
  registration, which is not a contract). It is safe TODAY because no foreign key
  crosses a module boundary (every FK is intra-module: `role_assignments` /
  `role_permissions` -> `roles`, `team_members` -> `teams`). A future cross-module
  FK would need an explicit ordering mechanism (a declared priority), not a reliance
  on registration order - called out so it is not assumed.

## 5. The hard-delete operation

`POST /api/v1/platform/tenants/{tenantId}/erase`, `RequirePlatformAdmin` (the
super-admin plane, bypass), body `{ "force": false }`:

**All four steps run in ONE bypass transaction, committed once**, so an erased
tenant can never exist without its audit record and no concurrent status change can
race the purge. This matches every other control-plane write in the codebase (grant
/ revoke admin, impersonation, plan CRUD all commit state + audit together).

1. Load the target tenant `SELECT ... FOR UPDATE` (the row lock is essential: now
   that `deleted -> active` reactivate exists, a concurrent reactivate could
   otherwise flip the tenant back to active between the retention check and the
   delete, erasing a just-restored tenant). It MUST be `status = deleted` (else 409
   `starter:tenant-state`); and either `deleted_at + RetentionDays <= Clock.UtcNow`
   or `force == true` (else 409 with a detail naming when the window elapses). A
   missing tenant is 404.
2. PRODUCE the final export snapshot from the erasure declarations: for each
   declared table, `select * from {table} where {keyColumn} = @tenantId`, into a raw
   JSON snapshot, with the two secret columns (`service_accounts.key_hash`, the
   webhook signing secret) REDACTED. This is the operator's pre-purge compliance
   record; return it in the response so the operator captures it. (It is a raw
   row snapshot, distinct from the shaped section-3 self-serve export; both draw
   from the same tenant, one shaped for the subject, one raw for the operator.)
3. ERASE via `ITenantErasureService` (section 4) - the per-module declared deletes
   plus the session revoke.
4. RECORD `platform.tenant.erased` on `platform_audit_log` through the
   `IPlatformAuditWriter` (the impersonation/plan-change pattern) - the durable
   record of who erased which tenant when, on the log that is NOT purged. Added to
   the `AuditLogTests` NotAudited set (no async consumer subscribes; it is written
   synchronously on the bypass path). Then COMMIT.

A second erase of an already-gone tenant is a 404 (the row is gone).

## 6. Events and audit

- Self-serve export emits `tenancy.tenant.data_exported` (tenant-scoped, deliverable):
  a bulk data access is worth auditing and worth a webhook (a security team may want
  to know). Payload: actor and a per-section row-count summary, no data copy.
- The hard delete records `platform.tenant.erased` on the platform audit log
  synchronously (section 5.4). It is NOT a tenant-scoped domain event: a
  tenant-scoped event would ride the tenant's own outbox / audit log, which the
  erasure is purging, so it would be destroyed or dangle. The platform log is the
  correct, surviving home.
- The existing `tenancy.tenant.soft_deleted` is unchanged; `deleted_at` is now
  stamped alongside the status change.

## 7. Individual-user DSAR (documented, not built)

The committed scope is tenant-scoped (the tenant is the controller in this B2B
model; an individual's request is served through their tenant). A per-USER export
(one data subject's personal data across the tenant) and per-user ERASURE
(anonymize a user's PII - tombstone the email/name while retaining the user id, so
audit actor ids and `created_by` references keep their integrity) are the natural
next step and reuse these seams: the export contributor gains a user-filtered
overload, and erasure becomes anonymization (UPDATE to a tombstone) rather than
DELETE for the global `Identity` user. Deferred; noted so the seam is intentional.

## 8. The secret-exclusion obligation (both paths)

Two tenant-owned columns hold credential material and must never appear in an export
or snapshot: `service_accounts.key_hash` (a credential hash) and the webhook
endpoint's encrypted signing secret. The self-serve export omits them by shaping in
each contributor (section 3); the operator snapshot redacts them by name (section
5.2).

**Enforce this with a COMPLETENESS mechanism, not an enumerated test.** A test that
just names those two columns cannot catch a THIRD secret column a future increment
adds (an SSO client secret, an outbound-API token): the fixed test still passes and
the secret leaks in both artifacts. Instead, mark every secret-bearing property with
a `[Sensitive]` attribute, and add a reflection-based test that fails the build if
ANY `[Sensitive]` property on ANY `ITenantOwned` type appears in either the export
bundle or the operator snapshot. This mirrors the codebase's own
`AuditLogTests.CatalogueCompleteness` discipline (every event type must be
explicitly audited-or-not, enforced by reflection), so a new secret column is caught
by construction, not by remembering to update a list.

## 9. Deferred (documented grow-into, not built)

- Async large-tenant export to an object-store artifact with a signed, expiring
  download URL (the self-serve endpoint returns a job handle instead of the bundle).
- Per-user DSAR: user-scoped export and PII anonymization (section 7).
- A scheduled sweeper that hard-deletes tenants whose retention window has elapsed,
  instead of an operator calling the endpoint (reuses the same service).
- Export format negotiation (CSV/JSONL per section) and a documented schema for the
  bundle, for machine re-import.
- Legal-hold: a flag that blocks erasure for a tenant under investigation, checked
  before step 1.

## 10. Deletability

Mostly additive and removable: drop `IDataExportContributor` + the per-module
contributors + `ITenantExportService` + the `/export` endpoint + the `data:export`
atom (and its `NotServiceAccountGrantable` entry); drop `ITenantErasureContributor` +
the per-module declarations + `ITenantErasureService` + the `/erase` endpoint; drop
the `deleted_at` column, `DsarOptions`, the two event-spine indexes, and the
`[Sensitive]` attribute. TWO small edits are modifications rather than pure
additions and would be reverted on removal: the `deleted -> active` widening of
reactivate, and the `deleted_at` stamping/clearing in the soft-delete/reactivate
paths. The rest of the soft-delete lifecycle from Part I is untouched. Nothing else
references export or erasure.
