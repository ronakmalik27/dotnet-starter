# ABAC: conditional grants over RBAC

Status: DESIGN (proposed). The twelfth (and final) SaaS grow-into feature
(multi-tenancy.md section 21: "A policy engine (ABAC): conditional grants (time,
IP, resource attributes) through an engine such as Cedar or Open Policy Agent,
evaluated at the same per-request permission check (section 13). RBAC stays the
default; ABAC layers on only when a customer's rule needs a condition"). Docs-first:
nothing here is built until this revision is reviewed.

**Built as an integration SEAM, deliberately, not a from-scratch policy engine.**
Hand-rolling a general attribute-based policy language (a Rego or Cedar of our own)
is below-par AND the most expensive option: policy languages are their own products,
and a bespoke one is an unbounded surface with its own evaluation-safety footguns
(non-termination, injection through attribute values, silent fail-open). The right
engineering call for a starter is a CORRECT minimal path: a grant may carry ONE
optional condition, evaluated at the existing per-request permission check against a
small, fixed request-attribute bag, through a pluggable evaluator registry. Two
built-in condition kinds (an IP-CIDR allowlist and a UTC time-of-day window) prove the
seam end to end; a real policy engine (Cedar, Open Policy Agent) plugs in as ONE more
evaluator registered for its own condition type, with no change to the gate, the
resolver, or the schema (section 4). RBAC stays the default and the whole feature is a
no-op until a customer attaches a condition to a grant.

## 1. The decision, up front

- **ABAC layers on RBAC; it never replaces it.** A grant is still a binding of a
  custom role to a principal at a scope (multi-tenancy.md section 13). ABAC adds ONE
  optional field to that binding: a `condition`. When the condition is absent (every
  grant today), the grant behaves exactly as it does now. When present, the grant's
  permissions count only for a request whose attributes satisfy the condition.
- **The condition is evaluated at the SAME per-request permission check as RBAC**
  (`RequirePermission`, multi-tenancy.md section 13), not in a separate pipeline. This
  is the section-21 commitment: conditions plug into the existing gate, so there is
  one authorization decision point, not two.
- **The evaluation is per request and per check, never memoized as a static grant.**
  This is the load-bearing invariant (section 5). The effective-permission set the
  resolver caches per request is the set of UNCONDITIONAL grants only; a conditional
  grant is deliberately kept OUT of that cached set and evaluated live against the
  request attributes each time it is consulted. Folding a conditional grant into the
  cached set would memoize a decision under a key that omits the very attributes the
  condition reads - the one way a naive design breaks.
- **Fail-closed, always.** A condition that is unknown, malformed, references a missing
  attribute, or errors during evaluation denies the grant (the permission is simply not
  conferred). This matches the RBAC resolver's fail-closed contract (an unresolved
  membership is the empty set) and is the opposite of the commercial gates
  (`RequireEntitlement` / `RequireQuota`), which fail OPEN by design. A security
  condition that cannot be evaluated must never widen access.
- **Built-in conditions are single-clause on purpose.** `ip_cidr` and `time_of_day`
  each express one attribute test. Arbitrary boolean logic ("business hours AND from the
  office network AND on a resource labelled `prod`") is exactly what a real policy
  engine is for, and that is the documented Cedar / OPA plug-in (section 4, section 9):
  register a `cedar` evaluator and the condition payload becomes a policy reference. We
  do not grow a bespoke AND/OR mini-language.

## 2. Data model

One nullable column added to the existing `tenancy.role_assignments` grant row
(multi-tenancy.md section 17); no new table.

| column | type | notes |
|---|---|---|
| `condition` | `jsonb` null | NULL = unconditional (every grant today). When set, the condition envelope (section 3). Postgres validates it is well-formed JSON; the evaluator owns its semantics. Tenant policy config, NOT a secret - it is exported in the tenant DSAR bundle (section 8). |

The column attaches to the existing entity `RoleAssignment` as `public string? Condition
{ get; init; }`, mapped `HasColumnType("jsonb")`. The two partial unique indexes are
UNCHANGED: a principal still holds at most one grant of a given role at a given scope
(`ix_role_assignments_tenant_scope_unique`,
`ix_role_assignments_workspace_scope_unique`). A condition is an attribute OF that one
grant, not a way to hold the same role twice under different conditions - that (multiple
conditional grants of the same role at the same scope) is a documented grow-into
(section 9) that would widen the index, and it is not needed for the seam.

The migration adds only the column (no index change, no data backfill: existing rows
get NULL, which is the unconditional default). It follows the fail-closed RLS + FORCE
ROW LEVEL SECURITY pattern already on the table; the column inherits the table's
policy, so nothing new is needed at the policy level.

## 3. The condition envelope and the built-in kinds

A condition is a JSON object with a `type` discriminator plus type-specific fields:

```json
{ "type": "ip_cidr", "allow": ["203.0.113.0/24", "2001:db8::/32"] }
{ "type": "time_of_day", "startUtc": "09:00", "endUtc": "17:00" }
```

The `type` selects an evaluator from the registry (section 4). Two built-ins ship, each
reading exactly one attribute from the request bag:

- **`ip_cidr`** - satisfied iff the request's client IP is inside one of the `allow`
  CIDR ranges (IPv4 or IPv6). Reads `RequestAttributes.ClientIp`. Fail-closed if the
  client IP is unknown or unparseable, or if `allow` is empty. This is the classic
  network-conditional-access rule (Okta / Entra Conditional Access "trusted network"):
  a grant that only counts from the corporate egress range or a VPN CIDR. It is the
  natural fit for a service-account key restricted to a CI runner's IP range.
  Two implementation obligations the evaluator MUST honor: (a) normalize an
  IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, which a dual-stack Kestrel listener
  reports for an IPv4 client) back to IPv4 before matching, else a plain IPv4 CIDR
  never matches (fails closed, so it locks callers out rather than leaks - but it is
  a correctness bug); (b) `Validate` bounds the `allow` list to a sane maximum
  (e.g. 64 entries) so a pathological payload cannot bloat a grant row.

  **Deployment prerequisite (loud).** `ClientIp` is only trustworthy behind a
  correctly configured forwarded-headers setup. `HttpContext.Connection.RemoteIpAddress`
  is the last socket hop; behind a reverse proxy, load balancer, or CDN (the default
  deployed topology) that is the PROXY's address, not the caller's, so an unconfigured
  deployment makes an `ip_cidr` condition either a silent no-op (the proxy IP happens
  to sit in the range) or a silent lockout of every caller. The host MUST wire
  `ForwardedHeadersMiddleware` with an EXPLICIT, non-empty `KnownProxies` /
  `KnownNetworks` allowlist (never the wildcard-trust default - `X-Forwarded-For` is
  client-writable, so trusting it from an untrusted hop is an IP-spoofing vector).
  With that middleware in place, `RemoteIpAddress` is the correct rewritten client
  address and the seam reads the right property. This starter does NOT enable
  forwarded-headers by default (it cannot know the operator's proxy IPs): until the
  operator configures it, `ip_cidr` must be treated as not-yet-usable (section 8). The
  `time_of_day` kind has no such dependency.
- **`time_of_day`** - satisfied iff the request time falls within the `[startUtc,
  endUtc)` window (both `HH:mm`, UTC). Wrap-around past midnight is supported
  (`startUtc` > `endUtc` means the window spans midnight). Reads
  `RequestAttributes.Now`, which the gate stamps from the injected `Clock` (never
  `DateTimeOffset.UtcNow` directly - the BannedApi arch test forbids it). This is the
  "business-hours only" rule and it is deliberately the kind that exercises the Clock
  path, so the time source is testable and mockable.

Resource-attribute conditions (a grant that only counts on a resource with a given
label or status) are NOT a built-in: they need a richer resource contract than today's
`IOwnedResource` owner-id (multi-tenancy.md section 5, layer 3), which is genuinely
more work and is the province of a real policy engine. `RequestAttributes` carries a
`ResourceId` slot so the seam is shaped for it, but no built-in consumes it; it is a
documented grow-into (section 9).

## 4. The evaluator seam (the Cedar / OPA plug-in point)

Two Platform contracts, both in `Starter.Platform/Auth/Conditions/` (Platform, because
they are pure BCL - `System.Net`, `System.Text.Json` - and a module may not be
referenced from Platform):

```csharp
// One condition KIND. Stateless. The pluggable seam.
public interface IConditionEvaluator
{
    // The discriminator this evaluator handles, e.g. "ip_cidr".
    string ConditionType { get; }

    // Called at GRANT time: throw ConditionFormatException on a malformed payload
    // (a typo'd CIDR, a bad time). Rejecting at write time turns a silent
    // never-satisfied grant into a clear validation error.
    void Validate(JsonElement condition);

    // Called at CHECK time. MUST fail closed: return false on any doubt (missing
    // attribute, parse slip). Never throw for a data reason - Validate already ran.
    bool IsSatisfied(JsonElement condition, RequestAttributes attributes);
}

// The request-attribute bag the gate assembles (immutable, per request).
public sealed record RequestAttributes
{
    public required DateTimeOffset Now { get; init; }   // stamped from the injected Clock
    public required IPAddress? ClientIp { get; init; }  // http.Connection.RemoteIpAddress (trustworthy only behind configured forwarded-headers - section 3)
    public Guid? WorkspaceId { get; init; }             // resolved workspace, when workspace-scoped
    public Guid? ResourceId { get; init; }              // route resource id; no built-in reads it yet (section 9)
}
```

A small registry, `ConditionEvaluatorRegistry` (Platform, singleton), holds a frozen
`ConditionType -> IConditionEvaluator` map built from the registered evaluators and
exposes two dispatching methods:

- `Validate(string conditionJson)` - parse the envelope, require a non-empty known
  `type`, delegate to that evaluator's `Validate`. Throws `ConditionFormatException`
  on an unknown type or a bad payload. Used by the grant path (section 6).
- `IsSatisfied(string conditionJson, RequestAttributes attributes)` - parse, look up
  the evaluator by `type`, delegate. **Fail-closed**: an unknown type returns false;
  a parse failure returns false; an evaluator that throws is caught and returns false.
  Used by the conditional-grant resolver (section 5).

**This registry IS the Cedar / OPA integration point.** A real policy engine ships as
ONE `IConditionEvaluator` whose `ConditionType` is, say, `cedar`, whose condition
payload is a policy reference (`{ "type": "cedar", "policyId": "..." }`), and whose
`IsSatisfied` calls the engine with the request attributes projected as the engine's
entity/context set. Registering it adds a condition kind; it changes nothing in the
gate, the resolver, the schema, or the two built-ins. That is the whole point of the
seam: the grow-into is additive registration, not a rewrite.

## 5. Evaluation at the permission check (the load-bearing invariant)

The RBAC resolver (`PermissionResolver`, multi-tenancy.md section 13) caches the
caller's effective permission set per request, keyed on `(principal, workspace,
principalType)` - a key that OMITS every request attribute a condition reads (clock,
IP, resource). Therefore a conditional grant must never enter that cached set. The seam
splits resolution into two tiers:

**Tier 1 - unconditional grants (cached, unchanged behavior).** `PermissionResolver`
adds `AND condition IS NULL` to every grant query (tenant-scope, workspace-scope, and
both service-account queries). The resulting set is exactly today's set (every existing
grant has a NULL condition), it depends on no request attribute, so caching it per
request stays sound. **This filter is the safety hinge**: without it a conditional grant
would be read as unconditional and silently always-on. It is behavior-preserving today
and is covered by an explicit regression test (section 10).

**Tier 2 - conditional grants (evaluated live, never memoized as a decision).** A new
request-scoped `ConditionalGrantResolver` (Tenancy, `Rbac/`) reads the caller's grants
where `condition IS NOT NULL` - the SAME union logic as `PermissionResolver` (direct +
team grants for a user behind the active-membership gate; grants-only for a service
account; tenant-scope plus, when asked, the one workspace's scope), joined to each
role's permissions, carrying the condition JSON. It is a request-path RLS read (opens a
read transaction so the tenant GUC is set), NOT the bypass path, so it stays OUT of the
bypass allowlist - exactly like `PermissionResolver`.

Its port (Platform, `Auth/`) and the one method the gate calls:

```csharp
// Platform port, bridged to the Tenancy impl by the composition root (the
// IPermissionResolver pattern). One implementation, no drift.
public interface IConditionalGrantResolver
{
    // True iff the caller holds a CONDITIONAL grant conferring `permission` at the
    // scope whose condition is satisfied by `attributes`. Fail-closed: no such grant,
    // all conditions false, or any evaluation error -> false. workspaceId null = tenant
    // scope; a value adds that workspace's conditional grants (downward inheritance).
    Task<bool> IsGrantedAsync(
        Guid principalId, string principalType, string permission,
        RequestAttributes attributes, Guid? workspaceId, CancellationToken cancellationToken);
}
```

The resolver MAY cache the loaded grant ROWS per request (they do not change within a
request), but it MUST NOT cache the DECISION - it re-evaluates the condition against the
passed attributes on every call. Loading is lazy: the rows are fetched once, on the
first call in a request, and a caller with no conditional grants (every tenant that has
not adopted ABAC) gets an empty load and every subsequent check short-circuits to
false. So the feature costs nothing until a conditional grant exists. If the row cache
is keyed, it MUST be keyed by scope (`workspaceId`) exactly as `PermissionResolver`'s
dictionary is, so a tenant-scope load never serves a workspace-scope query; today the
gate calls `IsGrantedAsync` at most once per request, but the keying contract is stated
so a future caller cannot reintroduce a cross-scope cache bug.

**The gate.** `PermissionGate.InvokeAsync` and `InvokeWorkspaceAsync` gain a
conditional fallthrough AFTER the existing unconditional miss:

```csharp
var permissions = await tenancy.GetCallerPermissionsAsync(userId.Value, principalType, http.RequestAborted);
if (permissions.Contains(permission))
{
    return await next(context);            // Tier 1: unconditional grant. Unchanged.
}

// ABAC seam: a conditional grant may confer it under this request's attributes.
var clock = http.RequestServices.GetRequiredService<Clock>();
var conditional = http.RequestServices.GetRequiredService<IConditionalGrantResolver>();
var attributes = RequestAttributes.FromHttp(http, clock.UtcNow);   // Now, ClientIp, [WorkspaceId]
if (await conditional.IsGrantedAsync(userId.Value, principalType, permission, attributes, /*workspaceId*/ null, http.RequestAborted))
{
    return await next(context);            // Tier 2: conditional grant satisfied.
}

return TypedResults.Problem(StarterProblems.PermissionRequired(http));   // fail closed
```

The workspace overload passes the resolved `workspaceId` (the same one it already reads
from `IWorkspaceContext`) both into `attributes.WorkspaceId` and as the scope argument.
The Tier-2 branch runs only on a Tier-1 miss, so an authorized-by-RBAC caller pays
nothing; a genuine denial pays one extra RLS read (cached thereafter within the
request). Denials are the uncommon path, so this is the right trade for a starter, and
it keeps `IPermissionResolver` / `GetCallerPermissionsAsync` returning a plain set
(other callers are unaffected). `IConditionalGrantResolver` is a sibling port to
`IPermissionResolver`, deliberately not folded into the already-large `ITenancyApi`
facade: it is single-purpose and the gate resolves it directly.

## 6. The grant path: validation, threading, audit

- **`ITenancyApi.AssignRoleAsync`** gains a trailing `string? condition` parameter;
  `AssignRoleAsync` and `AssignRoleCoreAsync` thread it through. `null` is the ordinary
  unconditional grant.
- **Validation at write time.** When `condition` is non-null, `AssignRoleCoreAsync`
  calls `ConditionEvaluatorRegistry.Validate(condition)` BEFORE the insert; a
  `ConditionFormatException` maps to a Validation `Result.Failure`
  (`tenancy.condition_invalid`). So an unknown type or a malformed payload (a bad CIDR,
  a non-`HH:mm` time) is rejected at grant time, not silently never-satisfied.
- **Service accounts** hold a conditional grant through the ordinary
  `AssignRoleAsync` path, NOT the atomic create-with-role path. This increment does
  NOT add a `condition` parameter to `CreateServiceAccountAsync` /
  `ServiceAccountService.CreateAsync` (keeping the seam minimal): the IP-restricted-key
  case is create the account, then `AssignRoleAsync(..., condition)`. The brief window
  after creation before the conditional grant lands is fail-closed (the account has no
  permission yet), so it is harmless. Atomic create-with-conditional-role is a
  documented grow-into (section 9).
- **Audit.** `TenancyEvents.RoleAssignmentGranted` gains a nullable `conditionType`
  field on its payload (e.g. `"ip_cidr"`, or null for an unconditional grant), so the
  audit log and webhook subscribers record THAT a conditional grant was created and of
  what kind, without dumping the full policy. The raw condition is not put on the event.
  Adding the parameter touches every caller of the factory: `AssignRoleCoreAsync`
  passes the real type, and `InvitationAcceptor` (which inserts a `role_assignments`
  row directly on invite-accept, bypassing `AssignRoleCoreAsync`) passes
  `conditionType: null` - a scope-aware invitation's grant is always unconditional.
- **Visibility.** `ITenancyApi.ListAssignmentsAsync` /
  `ListWorkspaceAssignmentsAsync` result tuples gain a trailing `string? Condition` so
  the admin control plane can see which grants are conditional and render them; without
  this a condition would be invisible and unmanageable. The assignment-create endpoint
  DTO gains an optional `condition` object, passed through to `AssignRoleAsync`.
- **Revoke** is unchanged: a conditional grant is revoked by id like any other.

## 7. Fail-closed posture (the matrix)

Every uncertain outcome DENIES (the permission is not conferred). This is the RBAC
resolver's contract extended to conditions.

| situation | outcome |
|---|---|
| grant has NULL condition | Tier 1, unconditional, as today |
| condition type unknown to the registry | deny (registry returns false) |
| condition JSON malformed at check time | deny (caught, false) - should not happen: `Validate` ran at write time |
| evaluator throws at check time | deny (caught, false) |
| `ip_cidr` with unknown/unparseable client IP | deny |
| `time_of_day` outside the window | deny |
| caller has no active membership | deny - the conditional resolver applies the SAME active-membership gate as `PermissionResolver`, so a suspended member reaches no conditional grants either |
| condition satisfied | allow |

The registry is the only place an "unknown type" is decided, and it decides DENY. There
is no path where an unrecognized or unparseable condition widens access.

## 8. Placement, arch tests, deletability

- **Platform** (`Auth/` and `Auth/Conditions/`): `IConditionEvaluator`,
  `RequestAttributes`, `ConditionFormatException`, `ConditionEvaluatorRegistry`, the two
  built-ins (`IpCidrConditionEvaluator`, `TimeOfDayConditionEvaluator`), and the
  `IConditionalGrantResolver` port. All pure BCL, so Platform (which may reference only
  SharedKernel) is legal - verified by `DependencyShapeTests`.
- **Tenancy** (`Rbac/`): `ConditionalGrantResolver` (the RLS read + dispatch) and the
  `PermissionResolver` Tier-1 filter change. `ConditionalGrantResolver` is a request-path
  RLS read and MUST stay OUT of the `TenancyAllowlist` bypass set
  (`BypassDataSourceContainmentTests`), exactly like `PermissionResolver`.
- **DI.** The two built-in evaluators + the registry register in
  `StarterAuthorization.AddStarterAuthorization` as singletons (stateless). The
  `ConditionalGrantResolver` registers scoped in `TenancyModule`, with the
  `IConditionalGrantResolver` bridge pointing at it (the `IPermissionResolver` bridge
  pattern), so there is one implementation and no drift.
- **Clock.** The time evaluator reads `RequestAttributes.Now`; the gate stamps it from
  the injected `Clock`. No `DateTimeOffset.UtcNow` anywhere in the feature
  (`BannedApiTests`).
- **Catalogue.** Conditions are a SEPARATE axis from permissions: a condition is never a
  permission atom, so `Permissions` and its closed catalogue / subset validation are
  untouched (`Permissions.IsKnown` still gates role composition).
- **Deployment prerequisite (`ip_cidr`).** `ip_cidr` is meaningful only behind a
  forwarded-headers setup with an explicit trusted-proxy allowlist (section 3). The
  starter ships forwarded-headers OFF by default (it cannot know the operator's proxy
  IPs) and documents the operator obligation; `time_of_day` has no such dependency and
  is usable immediately.
- **Deletability.** Dropping the feature is: drop the `condition` column (or leave it
  NULL), remove the Tier-2 branch from the gate, and unregister the evaluators. Tier 1
  is unchanged RBAC, so removal degrades cleanly to today's behavior.

## 9. Grow-into (documented, not built)

- **A real policy engine (Cedar, Open Policy Agent)**: register one
  `IConditionEvaluator` for a `cedar` / `opa` type whose payload is a policy reference,
  projecting `RequestAttributes` (widened as needed) into the engine's entity/context
  set. This is the section-21 "engine such as Cedar or OPA" and the seam is shaped for
  it (section 4) with zero change to the gate, resolver, or schema.
- **Resource-attribute conditions**: a grant conditioned on a resource's label / status
  / owner needs a richer resource contract than today's `IOwnedResource` owner-id
  (multi-tenancy.md section 5). `RequestAttributes.ResourceId` is the seam slot; a
  resource-loading step would populate a resource-attribute view for the evaluator.
- **Boolean composition and multiple conditional grants of one role**: an `all_of` /
  `any_of` envelope, and/or letting a principal hold the same role at the same scope
  under several conditions (which widens the partial unique index to include a condition
  hash, or moves conditions to a child table). Not needed for the seam; arbitrary logic
  is better served by the Cedar plug-in.
- **Condition on the tenant base role / system roles**: conditions attach to custom-role
  grants only (the `role_assignments` row). Conditioning a system role would be a
  different mechanism and is out of scope.
- **Atomic create-service-account-with-conditional-role**: threading `condition`
  through `CreateServiceAccountAsync` so an IP-restricted key and its conditional grant
  are created in one call. Today that is a two-step (create, then `AssignRoleAsync`
  with the condition - section 6); the atomic form is a small, additive extension.

## 10. Tests (added to the crown-jewel suite)

- **The segregation invariant (headline)**: a caller holds a conditional grant of
  `notes:write` whose condition is currently FALSE (an `ip_cidr` the request IP is not
  in). `GetCallerPermissionsAsync` does NOT contain `notes:write` (it never enters the
  cached unconditional set), and the gated endpoint 403s. A companion unconditional
  grant of a different permission still resolves. This proves Tier 1 excludes
  conditional grants. Assert the cached set DIRECTLY (not only the endpoint status) and
  cover ALL FOUR of `PermissionResolver`'s grant queries: tenant-scope and
  workspace-scope, each for a user grant and a service-account grant. Each path has a
  distinct `condition IS NULL` filter; an end-to-end status-code test alone would pass
  by coincidence whenever Tier 2's live evaluation happens to agree, so the direct
  set assertion on every path is what actually guards the safety hinge.
- **Live evaluation flips across requests**: the SAME conditional `ip_cidr` grant -
  request from an in-range IP 200s; request from an out-of-range IP 403s. And a
  `time_of_day` grant: inside the window 200s, outside 403s (Clock mocked). This proves
  Tier 2 evaluates live against the request attributes.
- **Fail-closed**: an unknown condition type denies; a grant whose evaluator would throw
  denies; a `ip_cidr` with no resolvable client IP denies; a suspended member reaches no
  conditional grant (the membership gate).
- **Grant-path validation**: assigning a role with a malformed condition (bad CIDR,
  non-`HH:mm` time, unknown type) is a Validation failure (`tenancy.condition_invalid`)
  and writes no row; a well-formed condition is accepted and round-trips through
  `ListAssignments` and the DSAR export.
- **Service account**: a conditional `ip_cidr` grant on a service-account key confines
  it to the range (in-range 200s, out-of-range 403s).
- **Cross-tenant**: tenant A's conditional grant is invisible to tenant B (RLS), like
  every other `role_assignments` read.
- **DSAR + secrets**: the `condition` column appears in the tenant export (it is tenant
  policy, not a secret); no secret is introduced by this feature (the `[Sensitive]`
  completeness test is unaffected).

## 11. Build sequence (this increment)

1. Migration: add `condition jsonb` null to `tenancy.role_assignments`; map
   `RoleAssignment.Condition`.
2. Platform: `RequestAttributes`, `IConditionEvaluator`, `ConditionFormatException`,
   the two built-ins, `ConditionEvaluatorRegistry`, `IConditionalGrantResolver`;
   register evaluators + registry in `AddStarterAuthorization`.
3. Tenancy: the `PermissionResolver` Tier-1 `condition IS NULL` filter on all four
   grant queries (the safety hinge); `ConditionalGrantResolver` + the
   `IConditionalGrantResolver` bridge in `TenancyModule`; thread `condition` through
   `AssignRoleAsync` / `AssignRoleCoreAsync` with registry validation; the
   `RoleAssignmentGranted` `conditionType` payload field, updating BOTH factory call
   sites (`AssignRoleCoreAsync` passes the type; `InvitationAcceptor` passes null); the
   `condition` on the `ListAssignments*` tuples and the DSAR RoleAssignments
   contributor. `CreateServiceAccountAsync` is NOT changed (service-account conditions
   go through `AssignRoleAsync` - section 6).
4. Api: the gate Tier-2 fallthrough (`RequestAttributes.FromHttp`, resolve
   `IConditionalGrantResolver`); the assignment-create endpoint's optional `condition`.
5. Tests (section 10), then the full live suite.
