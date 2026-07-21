# Onboarding

Clone to productive, in order. This is the guided path; the [README](README.md)
is the full tour and `AGENTS.md` is the operating contract. If you are an AI
agent, read `AGENTS.md` first, then this.

## What you are looking at

A generic .NET 10 modular-monolith backend: one deployable host
(`Starter.App`) composing independent modules (`src/Modules/`), each behind a
narrow public interface, over shared machinery (`Starter.Platform`) and domain
primitives (`Starter.SharedKernel`). The dependency graph flows one way:
`SharedKernel <- Platform <- Modules <- Api <- App`. Only the host references
everything; nothing references the host back.

## 1. Prerequisites

- The **.NET 10 SDK**. On a non-interactive shell it may be off PATH:
  `export PATH="$HOME/.dotnet:$PATH"`.
- A running **Docker daemon** - the integration suite boots a real Postgres
  Testcontainer, and `docker compose` is the easiest way to run the app.

## 2. Run it

```
docker compose up --build
```

Postgres and the app start; the host applies every module's migrations on boot
and serves on 8080. Check `http://localhost:8080/readyz` (green once Postgres is
reachable and all migrations are applied) and, in Development, the API reference
UI at `http://localhost:8080/scalar`. The README's "Running it" section covers
the SDK-only path and the configuration keys.

## 3. Build and test

```
export PATH="$HOME/.dotnet:$PATH"
dotnet build Starter.slnx -c Release
dotnet test  Starter.slnx -c Release
```

The build is strict on purpose (`Directory.Build.props`): nullable reference
types on, **warnings as errors**, and **locked** package restore. The unit and
architecture suites need no database; the integration suite needs Docker.

Know this gotcha up front: warnings-as-errors plus the transitive NuGet audit
means a newly-disclosed advisory against a package you never touched can break
an otherwise-unchanged build the day it lands. That is intended - a fresh
vulnerability should stop the line. The fix is to bump the affected package's
central pin in `Directory.Packages.props` forward and re-restore (see the note
in `AGENTS.md`).

## 4. The architecture in sixty seconds

- Each module assembly exports exactly two public types: its `I<Module>Api`
  interface and its `<Module>Module` bootstrap class. Everything else is
  `internal`, including the DbContext and the migrations.
- Modules never reference each other; the host composes them and passes results
  across boundaries.
- `tests/Starter.Architecture.Tests` fails the build on a violation, so these
  are enforced, not aspirational. `Starter.Sample` is the worked example to copy
  (an authenticated, owner-scoped resource with create / read / delete / keyset
  list).

## 5. The invariants you must not break

When you touch a feature, keep these intact - they are wired and enforced.
`AGENTS.md` is the authoritative list; the short version:

- **Time and ids** flow only through the SharedKernel: inject `Clock`, use `Ids`
  (UUIDv7). `DateTime.UtcNow` and `Guid.NewGuid` are banned outside the kernel.
- **RFC 9457 problems.** Every error is `application/problem+json` with a stable
  `starter:*` type; map through `StarterProblems`, never hand-roll a body.
- **Transactional outbox.** A domain event and its outbox rows commit in the
  same transaction as the state, on the append-only `domain_events` spine;
  enqueue through `OutboxWriter` inside the business transaction. Never put a raw
  secret or PII on the spine.
- **Idempotency.** A mutating endpoint behind `RequireIdempotency` enlists the
  filter's transaction so the write and the stored response commit together;
  `CreateNoteHandler` is the worked example.
- **Resource-based authorization.** The token carries no roles or scopes;
  authorize per request against the entity (`IOwnedResource` +
  `IAuthorizationService`), and filter owner-scoped lists in the query itself.
- **Validated options.** Bindable options validate at startup
  (`ValidateDataAnnotations` + `ValidateOnStart`); keep shipped defaults valid so
  a zero-config host still boots.
- **Secrets never in the repo.** `dotnet user-secrets` locally, a managed store
  in production.

## 6. Add your first module

Follow the README's "Adding a module" recipe (copy `Starter.Sample`, rename the
interface / module / DbContext, model the entity with `Ids` + `Clock`, generate
an `internal` initial migration, register it in `Program.cs` and the
architecture-tests module list). Do not reinvent it; the recipe is the contract.

## 7. Ship it

Push a version tag and CD takes over:

```
git tag v1.2.3
git push origin v1.2.3
```

`.github/workflows/cd.yml` builds the container image and pushes it to GHCR; the
`deploy` job is a clearly-marked stub gated on a `production` environment - swap
its one step for your target. See the README's "Releasing" section.

## If you are an AI agent

`AGENTS.md` (and its `CLAUDE.md` pointer) is your contract: the build/test
commands, the enforced module boundaries, and the invariants above. This repo
ships no workflow of its own - the full docs-first process and the review gates
live in the companion `project-starter` template; apply them from there when this
repo is used inside that workflow.
