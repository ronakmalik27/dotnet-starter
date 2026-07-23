# In-app notifications

Status: DESIGN (proposed). The eighth SaaS grow-into feature (multi-tenancy.md
section 21, "In-app notifications"). Docs-first: nothing here is built until this
revision is reviewed. It is the closest sibling to the audit log: a per-USER inbox
PROJECTED from domain events by a Platform consumer, exactly as the audit log is a
per-TENANT trail projected from the same events. Read audit-log.md sections 2-3
first; this doc is largely "the audit projection, but targeted at one recipient."

## 1. The decision, up front

- **A notification is a targeted projection of a domain event, not a new write
  path.** The event already happened and is already on the outbox; a Slow-lane
  Platform consumer turns a curated subset of events into per-recipient inbox rows,
  the same shape as the audit projection (audit-log.md section 2) but keyed on a
  recipient user instead of the whole tenant. Nothing new is emitted; notifications
  ride the existing consumer spine (the committed hook, section 21).
- **Two channels, one concept; in-app is what this increment adds.** The existing
  `IdentityNotificationsConsumer` already emails a user off events ("was this you",
  "password changed") via `IEmailSender` - that is the EMAIL channel, and
  it is the other half of the committed "ride the existing `IEmailSender` and
  consumer pattern." This increment adds the IN-APP channel: a persisted inbox the
  user reads through the API. A per-user, per-type channel PREFERENCE (in-app vs
  email vs both) is a documented grow-into (section 8), not built; the two channels
  are independent consumers today.
- **Notifications are TARGETED; the audit log is COMPREHENSIVE.** The audit
  projection subscribes to every tenant-scoped event (`DeliverableEvents.TenantScoped`).
  A notification only makes sense when an event has a clear single USER it happened
  TO, so the notification consumer subscribes to a small CURATED set (section 3), not
  the whole catalogue. Most events (a workspace renamed, a plan changed) have no one
  natural recipient and are deliberately not notified in-app.
- **The inbox is per (user, active tenant).** A user belongs to many tenants; a
  notification is created within a tenant (it is tenant-owned, RLS), and the reader
  sees only their OWN notifications within the tenant they are currently acting in
  (the `tid` token's tenant). This matches the one-tenant-at-a-time session model.
- **Reading your own inbox needs no permission.** Any authenticated tenant member
  reads, counts, and marks read their OWN notifications - it is their own data, so
  the endpoints gate on `RequireTenant` + `RequireAuthorization` and filter
  `recipient_user_id = caller`, with no new permission atom. A member can never see
  another member's notifications (RLS scopes the tenant; the recipient filter scopes
  the user).

## 2. Data model

`platform.notifications`, tenant-owned, RLS (`ITenantOwned` + FORCE RLS + the standard
`tenant_isolation` policy). Hosted in `PlatformDbContext` (cross-cutting, consumes
untyped events, like the audit log and webhooks).

| column | type | notes |
|---|---|---|
| `id` | uuid | PK (`Ids.NewId`) |
| `tenant_id` | uuid not null | the RLS discriminator, stamped from the event's tenant context on write |
| `recipient_user_id` | uuid not null | the user this notification is for (derived from the event, section 3) |
| `source_event_id` | uuid not null | the domain event this was projected from; the dedup key |
| `type` | text not null | the notification type (the source event type, e.g. `tenancy.member.role_changed`) |
| `data` | jsonb not null | render fields (ids and scalars only, no PII - the source payload is already PII-free) |
| `created_at` | timestamptz not null | when projected |
| `read_at` | timestamptz null | null = unread; set when the recipient marks it read |

- UNIQUE `(source_event_id, recipient_user_id)`: the dedup key. At-least-once
  redelivery of the same event re-projects the same (event, recipient) pair, hits the
  unique index, and the consumer treats the violation as success - idempotent by
  construction, the audit-projection discipline (audit-log.md section 2), but keyed on
  the pair so a single event MAY fan out to several recipients later without an id
  collision (today each curated event has exactly one recipient).
- Index `(tenant_id, recipient_user_id, created_at desc, id desc)` backs the inbox
  LIST (the keyset-cursor order from the pagination increment).
- PARTIAL index `(tenant_id, recipient_user_id) where read_at is null` backs the
  unread-count (polled every few seconds to drive a badge) and the read-all bulk
  UPDATE. Without it, a count-of-unread walks the caller's ENTIRE history (the inbox
  is append-mostly with no purge, section 8), growing unboundedly over an account's
  lifetime, on every poll; the partial index stays small because unread rows are
  self-limiting (users clear them). This is the standard skewed-nullable-flag idiom.
- Normal request-role DML table (no boot REVOKE): the projection writes under RLS on
  the consumer scope, and the recipient reads/updates their own rows under RLS on the
  request path. Nothing operator-owned.

## 3. The projection consumer

`NotificationProjectionConsumer` (Platform, Fast lane), mirrors `AuditProjectionConsumer`
(audit-log.md section 2): references no module type, reads the payload by UNTYPED JSON,
resolves the request-style RLS-bound `PlatformDbContext` (never bypass), and the
dispatcher binds the event's tenant so the insert is RLS-scoped to it.

- **Fast lane**, like the audit projection and the webhook fan-out. `Lane.cs` defines
  the split as in-process DB write (Fast) vs an outbound provider call with a timeout
  (Slow) - it literally lists "in-app notification writes" as a Fast example. This
  consumer is a pure INSERT (no `IEmailSender`/HTTP call in `ConsumeAsync`, unlike the
  Slow-lane `IdentityNotificationsConsumer`), so Fast is correct AND it joins the
  existing Fast outbox row these four events already carry (audit + webhook), rather
  than minting a second Slow-lane row per event. A Slow lane would head-of-line-block
  a badge update behind an unrelated slow email.
- **A CURATED subscription with a recipient extractor per type.** `EventTypes` is a
  small explicit set, NOT `DeliverableEvents.TenantScoped`. Each subscribed type has a
  rule mapping the event to (recipient user, type, data):

  | Event | Recipient | Render data |
  |---|---|---|
  | `tenancy.membership.created` | the new member (`ActorUserId`) | payload `role` |
  | `tenancy.member.role_changed` | the affected member (payload `userId`) | payload `role` |
  | `tenancy.team.member_added` | the added user (payload `userId`) | `EntityId` (team) |
  | `tenancy.ownership.transferred` | the new owner (payload `newOwnerUserId`) | payload `previousOwnerUserId` |

  These are the events that name exactly one clear recipient USER (verified against
  the `TenancyEvents` factories). **There is NO actor-exclusion check.** The recipient
  is whatever the per-type rule reads, and that is the whole story: for the three
  admin-driven events the recipient is a PAYLOAD field (the affected member), which is
  inherently a different user from the acting admin (the tenant-admin service already
  rejects a self-targeting change), so the recipient is never the actor there. For
  `membership.created` the recipient IS the actor - because that event's `ActorUserId`
  IS the joining member themselves (self-provision or self-accept; there is no separate
  "who added them" identity on its schema), and notifying them ("you joined as {role}")
  is exactly the intent. A blanket `if (actor == recipient) skip` check would be WRONG:
  it would silently drop every `membership.created` notification forever. Do not add
  one; the per-type recipient mapping already yields the right target for each.
  `member.removed` is deliberately excluded: a removed member cannot see the tenant, so
  an in-app row they can never read is pointless (an email is the right channel - a
  grow-into).
- Dedup: insert; on the `(source_event_id, recipient_user_id)` unique violation, roll
  back and return success (redelivery). Exactly the audit projection's construction.
- Recipient resolution reads ONLY the event (`ActorUserId`, `EntityId`, and untyped
  payload fields). It does NOT query membership or resolve "all admins" - a broadcast
  or a fan-out-to-admins notification is a documented grow-into (section 8), kept out
  so the consumer stays a pure, module-free projection.

## 4. The inbox API

All under `RequireTenant` + `RequireAuthorization`, all filtered to the caller's own
rows (`recipient_user_id = caller.sub`) under RLS. No permission atom.

- `GET /api/v1/tenant/notifications` - the caller's notifications, newest first,
  keyset-paginated (the `CursorPage` codec from the pagination increment), optional
  `?unread=true` to filter to unread only.
- `GET /api/v1/tenant/notifications/unread-count` - `{ "count": n }`, the caller's
  unread total (for a badge).
- `POST /api/v1/tenant/notifications/{id}/read` - mark one read (set `read_at` if
  null; idempotent). 404 if the id is not the caller's own notification (RLS +
  recipient filter make another user's or tenant's id invisible - so it reads as
  not-found, never forbidden).
- `POST /api/v1/tenant/notifications/read-all` - mark all the caller's unread rows
  read in one statement; returns the count marked.

Marking read is a WRITE the caller makes to their OWN rows; the `recipient_user_id =
caller` predicate on every update is the guard (a caller can only ever flip their own
rows). RLS is the tenant boundary underneath.

## 5. Placement and events

- The table, the consumer, and an `INotificationService` (the read/mark-read surface
  the API calls) live in Platform - the identical cross-cutting placement argument as
  audit-log.md section 9 and webhooks.md section 11. The consumer reads nothing
  module-specific (untyped payload), and the inbox depends on no module's data.
- Projecting a notification emits NOTHING (it is a terminal projection, like the audit
  log): no new domain event, no webhook, no re-entrant loop. Marking read emits
  nothing either - it is private per-user inbox state, not a tenant event worth
  auditing or fanning out.

## 6. What this is not

- Not a message BUS or a pub/sub between services (that is the outbox/consumer spine,
  already built). This is the human-facing inbox on top of it.
- Not real-time push (WebSocket / SSE). The API is poll-based (the unread-count
  endpoint backs a badge). A live push transport is a documented grow-into (section
  8); the persisted inbox is the source of truth a push channel would read from.

## 7. Deletability

Additive and removable: drop `platform.notifications` + its migration, the
`NotificationProjectionConsumer`, `INotificationService`, and the four endpoints.
The email channel (`IdentityNotificationsConsumer`) is untouched - it predates this
increment. Nothing else references the inbox.

## 8. Deferred (documented grow-into, not built)

- Per-user, per-type channel PREFERENCES (in-app / email / both / off), read by both
  the in-app consumer and the email consumer before delivering.
- Broadcast / fan-out-to-recipients notifications (notify all tenant admins of a plan
  change, all members of an announcement) - needs the consumer to resolve a recipient
  SET by querying membership, which couples it to the tenancy model, so it belongs
  behind a small Platform port rather than in the pure projection.
- Real-time push (WebSocket / SSE) reading the persisted inbox as its source.
- Email/in-app for the excluded events (`member.removed` -> an email, since the
  removed user has no inbox in that tenant).
- A retention / auto-purge policy for old read notifications (the inbox is otherwise
  append-mostly).
- The quota-exceeded and limit-reached notices the quotas increment deferred to here
  (quotas.md section 9): a throttled "you are near / at your limit" notification read
  off the usage counter, at most once per period.

## 9. Tests

Mirrors the audit-projection test categories (audit-log.md section 10):

- **Projection per curated type.** Each of the four curated events produces exactly
  one notification for the CORRECT recipient (the affected user), with the right type
  and render data. Especially: `membership.created` DOES notify the joining member
  (the actor-is-recipient case that a naive exclusion check would drop), and the three
  admin-driven events notify the affected member, NOT the acting admin.
- **Non-curated events produce nothing.** A `tenancy.workspace.created` (or any event
  not in the curated set) creates no notification row.
- **At-least-once redelivery is idempotent.** Forcing a redelivery of the same event
  does not create a second row (the `(source_event_id, recipient_user_id)` unique
  index; the violation is treated as success).
- **Cross-TENANT isolation.** Tenant A's notifications are invisible to a caller
  acting in tenant B (RLS).
- **Cross-USER isolation.** Within one tenant, user X never sees user Y's
  notifications, and `POST /{id}/read` on another user's notification id is a 404
  (invisible, not forbidden), leaving that row unread.
- **Mark-read and unread-count.** Mark-one and mark-all flip only the caller's own
  rows; unread-count reflects the change; mark-read is idempotent.
- **List pagination.** The keyset cursor pages the caller's inbox newest-first without
  gaps or duplicates, and `?unread=true` filters correctly.
