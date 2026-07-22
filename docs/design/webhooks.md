# Outbound webhooks

Status: DESIGN (proposed). The third SaaS grow-into feature (multi-tenancy.md
section 21, the "outbound webhooks" bullet). Docs-first: nothing here is built
until this revision is reviewed. It builds on the event spine and outbox
(multi-tenancy.md section 3), reuses the audit log's "Platform consumer projects
every module's events" placement (audit-log.md), and mirrors the outbox
dispatcher's leader-elected retry worker. Read those first.

## 1. The decision, up front

- **Delivery is two stages: a Fast fan-out consumer writes one delivery row per
  subscribed endpoint, and a SEPARATE background worker POSTs each row.** This is
  the industry-standard shape (Stripe, GitHub, Svix). The fan-out consumer is an
  `IDomainEventConsumer` (like the audit projection): for each domain event it
  inserts one `webhook_deliveries` row per tenant endpoint subscribed to that
  event type, transactionally and idempotently. The worker is a leader-elected
  `BackgroundService` (like `OutboxDispatcher`) that claims pending delivery rows
  and makes the HTTP call, with per-ROW retry and dead-letter.
- **Why two stages, and not "POST to all endpoints inside the consumer".** The
  outbox marks an event delivered once its consumer returns. If one consumer call
  POSTed to N endpoints and one endpoint was slow or down, the whole consumer
  would fail, the event would be re-fanned-out, and the endpoints that already
  succeeded would be POSTed AGAIN. Making each `(event, endpoint)` its own row
  with its own `attempts` / `next_attempt_at` / `dead_lettered_at` means each
  endpoint retries and dead-letters independently, and a healthy endpoint is
  never re-hit because a sibling failed.
- **Webhooks live in `Starter.Platform`, next to the outbox and the audit log.**
  Same three reasons as the audit log (audit-log.md section 9): the fan-out
  consumes every module's events through the event envelope (so it references no
  module and reads payloads as untyped JSON), and the cross-tenant delivery worker
  needs the bypass path to drain every tenant's `webhook_deliveries`. Platform
  legitimately owns `BypassDataSource`, so no new bypass-allowlist mechanism is
  needed - a module placement would require one. The two tables are RLS-owned
  (like the audit log), the second and third RLS tables in the platform schema.
- **The signing secret is recoverable, encrypted at rest, shown once.** Unlike an
  API key (hashed, never recovered), a webhook secret must be usable to HMAC-sign
  every delivery, so it is stored ENCRYPTED (via the already-wired DataProtection
  key ring persisted in `platform.data_protection_keys`) and decrypted at sign
  time. The raw secret is returned once at register and at rotate so the tenant
  can configure their verifier; after that only its ciphertext and a display
  prefix persist.
- **SSRF is a first-class threat, because the delivery URL is tenant-controlled.**
  A tenant admin registers the URL we then make server-side requests to, so an
  unguarded worker is a server-side request forgery primitive (cloud metadata,
  internal services, localhost). The design blocks it at two points: HTTPS-only at
  register time, and a `SocketsHttpHandler.ConnectCallback` that re-checks the
  RESOLVED ip against a blocklist on every connection, which also defeats DNS
  rebinding (a hostname that resolves public at registration and private at
  delivery).

## 2. Data model

Both tables tenant-owned, RLS-enforced (`ITenantOwned` + `enable`/`force row
level security` + the standard `tenant_isolation` policy), in the `platform`
schema.

`platform.webhook_endpoints`:

| column | type | notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid not null | RLS discriminator |
| `url` | text not null | HTTPS only; validated at register (section 6) |
| `description` | text not null | admin label |
| `event_types` | text[] not null | subscribed event types; empty = all deliverable |
| `signing_secret_encrypted` | text not null | DataProtection ciphertext (section 5) |
| `secret_prefix` | text not null | first chars of the raw secret, for display |
| `disabled_at` | timestamptz null | a disabled endpoint receives no new deliveries |
| `created_by` | uuid not null | |
| `created_at` / `updated_at` | timestamptz not null | |

`platform.webhook_deliveries`:

| column | type | notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid not null | RLS discriminator |
| `endpoint_id` | uuid not null | the target endpoint |
| `event_id` | uuid not null | the source domain event id |
| `event_type` | text not null | for display and filtering |
| `payload` | jsonb not null | the webhook body (envelope, section 5); stored so replay needs no event re-read |
| `status` | text not null | `pending` / `delivered` / `dead` |
| `attempts` | int not null | delivery attempts so far |
| `next_attempt_at` | timestamptz not null | when the worker may next claim it |
| `delivered_at` | timestamptz null | set on 2xx |
| `dead_lettered_at` | timestamptz null | set after `MaxAttempts` |
| `last_response_status` | int null | last HTTP status (or null on transport error) |
| `last_error` | text null | short, bounded, non-PII failure note |
| `created_at` | timestamptz not null | |

Unique `(endpoint_id, event_id)` on `webhook_deliveries` is the fan-out
idempotency key (section 3). A partial claim index `(next_attempt_at) where
status = 'pending'` serves the worker, mirroring the outbox poll index.

## 3. The fan-out consumer

`WebhookFanoutConsumer`, a Platform `IDomainEventConsumer`, Fast lane (it only
writes DB rows; the HTTP call is the worker). It subscribes to the deliverable
event catalogue (the tenant-scoped events, the same set the audit projection
lists). The dispatcher binds the scope to `event.TenantId`, so it runs RLS-bound
for exactly that tenant. Per delivery:

1. Read the tenant's `webhook_endpoints` that are not disabled and whose
   `event_types` is empty (all) or contains this event type. (RLS scopes this to
   the event's tenant automatically.)
2. For each matching endpoint, insert a `webhook_deliveries` row (`status =
   pending`, `attempts = 0`, `next_attempt_at = now`, `payload` = the webhook
   envelope built from the `DomainEventRecord`, `tenant_id` stamped from the
   tenant context, never the payload). The insert is idempotent: the unique
   `(endpoint_id, event_id)` catches a redelivered event as a no-op (the
   unique-violation-is-success pattern the audit consumer uses), so at-least-once
   redelivery never double-enqueues a delivery.

Payloads are read as untyped JSON (Platform cannot reference module payload
types), exactly as the audit projection does.

Two coupling notes. First, the fan-out consumer shares its Fast-lane outbox row
with the audit projection (`OutboxWriter` writes one row per `(event, lane)`, and
the dispatcher runs both consumers under one try/catch). Both are idempotent DB
writes in their own transactions, so a transient failure re-runs both harmlessly
(each no-ops on its unique key); the fan-out consumer is written to insert-and-
swallow the unique violation, never to throw on a benign redelivery, so it does
not poison the shared row. A genuinely stuck insert poisons and parks the row like
any outbox row, and the audit projection's own row is already durable from its
first attempt, so the two never corrupt each other. Second, because the delivered
body is the event payload verbatim, webhooks make the event catalogue's "ids and
scalars, never PII or secrets" rule an EXTERNAL boundary, not just internal
hygiene. That rule holds today (verified: no event payload carries a raw
key/token); a content-level guard asserting it for future event types is a
documented hardening, tracked with the audit log's same discipline.

## 4. The delivery worker

`WebhookDeliveryWorker`, a `BackgroundService` modelled on `OutboxDispatcher`:

- **Leader election**: its own `AdvisoryLock` with a distinct key (not the
  outbox's), so exactly one instance delivers; a non-leader idles and retries.
- **Claim**: on the BYPASS path (the deliveries table is RLS-owned, so a request
  -role connection with no tenant GUC sees zero rows; the worker must cross
  tenants). `select ... from platform.webhook_deliveries where status = 'pending'
  and next_attempt_at <= now() order by next_attempt_at for update skip locked
  limit N`, and in the same transaction arm a lease (`attempts = attempts + 1`,
  `next_attempt_at = now() + lease`) so a crashed leader's in-flight rows become
  reclaimable only after the lease, never mid-flight.
- **Re-arm per row on the lock session (the real double-send anchor)**: exactly as
  `OutboxDispatcher.RearmLeaseAsync`, immediately before each row's send the worker
  re-arms that row's lease by running the update ON THE ADVISORY LOCK'S OWN pinned
  session (`TryRunOnLockSessionAsync`). Success there proves the lock is still held
  at send time, so a failed-over leader cannot have already reclaimed the row - the
  claim-time lease alone is not enough (a batch of slow-but-alive sends can outlive
  a single per-tick liveness check). This step is mandatory, not optional.
- **Deliver**: load the endpoint (bypass); if it was deleted or disabled since
  fan-out, drop the delivery (mark it dead with a reason, do not POST) - the
  send-time re-check, since fan-out only filtered at enqueue. Otherwise `Unprotect`
  its signing secret, build the signature (section 5), and POST the stored
  `payload` through the SSRF-guarded HTTP client (section 6) with a timeout.
- **Outcome**: a 2xx sets `status = delivered`, `delivered_at = now`. Any other
  status, a transport error, or a timeout leaves it `pending` with
  `next_attempt_at` pushed out by an exponential backoff (`min(2^attempts,
  MaxBackoff) + jitter`, reusing the outbox `BackoffPolicy` shape) and records
  `last_response_status` / a bounded `last_error`. When `attempts` reaches
  `MaxAttempts` the row is dead-lettered (`status = 'dead'`, `dead_lettered_at =
  now`) and parked for replay - the exact analogue of an outbox poisoned row. A
  `Unprotect` failure (a lost or rotated-away key ring, section 5) is caught
  DISTINCTLY and dead-letters the row immediately with a clear reason rather than
  burning the whole retry budget on something that can never succeed.
- All tunables (advisory-lock key, batch size, max attempts, backoff cap, jitter,
  send timeout) live in a validated `WebhookOptions`, like `OutboxOptions`.

## 5. Signing and the payload envelope

- The body is a stable envelope: `{ id (delivery id), type (event type),
  occurredAt, data (the event payload) }`. `id` lets the receiver dedupe (delivery
  is at-least-once end to end).
- The signature is `HMAC-SHA256(secret, "{timestamp}.{body}")`, sent as a header
  `X-Starter-Signature: t=<unix>,v1=<hex>` (the Stripe scheme). The receiver
  recomputes and constant-time compares, and rejects a stale timestamp - so a
  captured request cannot be replayed later. The timestamp is signed, not just
  sent, so it cannot be altered.
- The secret is minted like an API key raw value (256-bit, base64url, an `whsec_`
  prefix so scanners catch a leak), returned ONCE at register and rotate, and
  stored only as DataProtection ciphertext (`IDataProtectionProvider.CreateProtector
  ("webhooks.signing-secret.v1")`, `Protect` on write, `Unprotect` at sign time).
  The key ring is persisted in `platform.data_protection_keys`, so every replica
  and every restart signs with the same keys. Rotate replaces the ciphertext and
  returns a new raw secret; the old secret stops signing immediately (a grace
  window with two active secrets is a documented extension).
- **The key ring is a single point of failure, called out as an operational
  obligation.** Because each secret is shown once and stored only as ciphertext,
  losing or corrupting `platform.data_protection_keys` makes EVERY tenant's secret
  unrecoverable at once. The DR requirement (that table is backed up with the
  database, never key-ring-on-ephemeral-storage) is documented, and the worker
  treats a `Unprotect` failure distinctly (section 4) so an operator gets a clear
  signal instead of a silent retry-until-dead.
- **The destination URL is kept out of traces.** OpenTelemetry HttpClient
  instrumentation is on and records the request URL by default, and a tenant's
  receiver URL can itself embed a secret (Slack / Discord / Teams incoming-webhook
  URLs carry the token in the path) - which this feature cannot prevent at
  registration. The webhook `HttpClient` therefore redacts or suppresses the URL on
  its own spans (a per-client enrichment), so a receiver-owned secret is not shipped
  to the OTLP backend. The app's HMAC secret and the signature header are already
  safe (default instrumentation captures no headers or bodies).

## 6. The SSRF guard

The delivery URL is tenant-controlled, so the guard is load-bearing, not
cosmetic. It has three layers.

- **At register / update time**: the URL must be absolute and `https` (a plaintext
  `http` URL, a non-absolute URL, or any non-`https` scheme is rejected, 422). As a
  fast-fail nicety the host is also resolved and range-checked here (an obviously
  internal literal target is rejected up front), but connect-time is the
  authoritative check - registration validation alone is a TOCTOU hole against
  rebinding.
- **At connect time (authoritative)**: the delivery `HttpClient` uses a
  `SocketsHttpHandler` with a `ConnectCallback`. The callback is handed an
  UNRESOLVED host+port, so it must be written to close the classic bypass:
  **resolve DNS exactly ONCE, validate every returned address, then open the socket
  directly to a validated `IPAddress` - never hand the hostname back to a second
  resolver for the actual connect.** Two resolutions (one to validate, one to
  connect) is the TOCTOU that rebinding exploits; resolving once and connecting to
  the vetted ip closes it. Redirects are NOT followed (a 3xx is a failed delivery),
  so a redirect cannot bounce to a blocked host after the check.
- **The address classifier** rejects, using the IANA IPv4/IPv6 special-purpose
  registries (not an ad-hoc subset). Before range-checking, an IPv4-mapped IPv6
  address (`::ffff:0:0/96`) is unwrapped with `MapToIPv4`, and NAT64
  (`64:ff9b::/96`), 6to4 (`2002::/16`), and Teredo (`2001::/32`) have their embedded
  IPv4 extracted and re-checked - otherwise an AAAA answer sails past an IPv4-only
  check. Blocked IPv4: `0.0.0.0/8`, `10/8`, `100.64/10` (carrier-grade NAT),
  `127/8`, `169.254/16` (link-local, incl. the `169.254.169.254` metadata
  endpoint), `172.16/12`, `192.0.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`,
  `198.51.100/24`, `203.0.113/24`, `224/4` (multicast), `240/4` (reserved, incl.
  `255.255.255.255`). Blocked IPv6: `::/128` (unspecified), `::1/128` (loopback),
  `fc00::/7` (unique-local), `fe80::/10` (link-local), `ff00::/8` (multicast). A
  bare `IPAddress.IsLoopback` is insufficient (it misses `0.0.0.0`, which a client
  connect typically lands on loopback), so the classifier checks explicit CIDRs.
- This is net-new code (the repo has no outbound-URL validation today); the
  classifier and the `ConnectCallback` live in Platform next to the worker and get
  their own unit tests (each blocked range, the IPv4-mapped/NAT64/6to4/Teredo
  unwrap, and a public address passing). A configurable allowlist of extra blocked
  or explicitly-permitted ranges is a documented extension (for example to permit a
  specific internal host in a trusted deployment).

## 7. Admin API

On the tenant group, gated by a new `webhooks:manage` permission (added to the
catalogue and `AdminSet`). Endpoints mirror the service-account shape:

- `POST /api/v1/tenant/webhooks` - register (url, description, event_types); returns
  the signing secret ONCE.
- `GET /api/v1/tenant/webhooks` - list endpoints (never the secret; only the
  prefix, url, subscribed types, disabled state).
- `PATCH /api/v1/tenant/webhooks/{id}` - update url / description / event_types /
  disabled.
- `POST /api/v1/tenant/webhooks/{id}/rotate-secret` - new secret, returned once.
- `DELETE /api/v1/tenant/webhooks/{id}` - remove the endpoint. There are no
  DB-level foreign keys in this codebase (every cross-table relationship is
  app/RLS-enforced), so the delete is an explicit transactional statement that
  removes the endpoint and its pending deliveries together; the worker's send-time
  re-check (section 4) covers a delivery already claimed when the delete lands.
- `GET /api/v1/tenant/webhooks/{id}/deliveries` - the delivery log (status,
  attempts, last response, timestamps), keyset-paginated.
- `POST /api/v1/tenant/webhooks/deliveries/{id}/replay` - reset a delivered, failed,
  or dead delivery to `pending` with `attempts = 0` so the worker re-sends it.

`webhooks:manage` is grantable in a custom role and, unlike `roles:manage` /
`api-keys:manage`, is NOT self-escalation, so it is not in
`NotServiceAccountGrantable` (a service account may manage webhooks). The
data-exfiltration consideration - a webhook forwards a tenant's events to an
external URL - is the same trust already placed in any admin-level permission and
is bounded by the SSRF guard (no internal targets) and the audit log (every
endpoint change is recorded).

## 7a. Bounds and fairness

The delivery worker is a single leader-elected instance draining a global FIFO by
`next_attempt_at`, so a few bounds keep one tenant from starving the rest:

- **A cap on endpoints per tenant** (configurable in `WebhookOptions`, a sane
  default), rejected at register with a clear 422, bounds the fan-out a single
  event can produce.
- **Per-tenant fairness and send concurrency** are explicitly the MVP's known
  scale limit: the worker sends serially within a batch (like the outbox), so a
  merely-slow endpoint delays the queue behind it. The documented scale-up is a
  bounded degree of parallel sends and a per-tenant round-robin claim, layered on
  the same claim/lease model without a schema change. A per-endpoint send-rate cap
  (so a burst of a tenant's own events cannot hammer an external target) rides the
  same options and is noted as the next bound to add.
- The send timeout bounds a single stuck endpoint (it fails the attempt and backs
  off rather than holding the worker), so "down" endpoints degrade to their own
  backoff schedule and do not block others indefinitely.

## 8. Events and audit

Endpoint lifecycle emits tenant-scoped events `tenancy.webhook.endpoint_created`
/ `.endpoint_updated` / `.endpoint_deleted` / `.secret_rotated`, added to
`AuditProjectionConsumer.EventTypes` (increment 8) so they are audited; the
catalogue-completeness test enforces the decision. Deliveries themselves are NOT
domain events (they are the projection of events, not new facts) - their record
is the `webhook_deliveries` log, queryable via the admin API.

## 9. Retention

Delivered delivery rows are purged after a retention window by a maintenance pass
on the bypass path (mirroring `OutboxMaintenance`), which keeps `dead` rows (the
dead-letter, for inspection and replay) exactly as the outbox keeps poisoned
rows. Endpoints persist until deleted.

## 10. Placement and deletability

Everything is in `Starter.Platform`: the two RLS tables mapped into
`PlatformDbContext`, the fan-out consumer, the delivery worker, the SSRF-guarded
HTTP client, and the Platform-registered admin services the Api endpoints call.
Deletability: drop the two tables, the consumer and worker registrations, the
endpoints, and the `webhooks:manage` atom, and the event spine is untouched.

## 11. Tests (added to the crown-jewel suite)

- **Fan-out is real and idempotent**: an event with two subscribed endpoints
  produces exactly two delivery rows; a forced redelivery of the event produces no
  more (unique `(endpoint_id, event_id)`). An endpoint that does not subscribe to
  the event type gets no row; a disabled endpoint gets no row.
- **RLS isolation**: a tenant sees only its own endpoints and deliveries; the
  fan-out for tenant A never creates a row for tenant B's endpoint.
- **Delivery succeeds and is signed**: a stub receiver gets a POST whose
  `X-Starter-Signature` verifies against the (rotated-in) secret and whose
  timestamp is fresh; the delivery row goes `delivered`.
- **Retry and dead-letter**: a receiver returning 500 causes `attempts` to climb
  with backoff and the row to dead-letter at `MaxAttempts`; a healthy sibling
  endpoint for the same event still delivers exactly once (one failure does not
  re-hit a success).
- **Replay**: replaying a dead delivery re-sends it and it can then succeed.
- **Secret is shown once, stored encrypted**: register/rotate return the raw
  secret; the list never does; the stored column is DataProtection ciphertext, not
  the raw secret, and `Unprotect` recovers it.
- **SSRF guard**: registering an `http://` or non-absolute URL is 422; a delivery
  to a URL that resolves to a loopback/private/link-local/metadata address fails
  (never connects), including the DNS-rebinding case (public at register, private
  at connect).
- **Audited**: endpoint create / update / delete / secret-rotate each land an
  audit row, and catalogue-completeness stays green with the new event types.

## 12. Build sequence (this increment)

1. Migration: `platform.webhook_endpoints` + `platform.webhook_deliveries` (RLS
   policies, the unique `(endpoint_id, event_id)`, the partial claim index).
2. Entities mapped in `PlatformDbContext` (both `ITenantOwned`, tenant filter).
3. `WebhookSecrets` (mint / prefix) + the DataProtection protector wrapper; the
   HMAC signer + the envelope builder.
4. `WebhookFanoutConsumer` (Fast, RLS, idempotent) + singleton registration; the
   deliverable event catalogue.
5. `WebhookDeliveryWorker` (`BackgroundService`, own advisory lock, bypass claim,
   per-row re-arm on the lock session, backoff, dead-letter, distinct
   `Unprotect`-failure handling, send-time endpoint re-check) + `WebhookOptions`
   (validated: advisory-lock key, batch size, max attempts, backoff cap, jitter,
   send timeout, max endpoints per tenant) + the SSRF-guarded named `HttpClient`
   (`SocketsHttpHandler.ConnectCallback` resolving once and connecting to the
   validated ip, redirects off) with URL redaction on its OTel spans +
   `AddHostedService`.
6. `webhooks:manage` in `Permissions.All` and `AdminSet`; the four new event
   types in `AuditProjectionConsumer.EventTypes`.
7. Platform admin services (RLS-bound register/list/update/rotate/delete and
   delivery list; the replay reset) + `WebhookEndpoints` on the tenant group.
8. Retention pass (bypass) that purges delivered, keeps dead.
9. Tests (section 11) added to the integration suite, plus unit tests for the SSRF
   ip classifier and the signature.
