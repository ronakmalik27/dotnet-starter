# AGENTS.md

Operating contract for an AI agent working in this repository. Thin by
design: the [README](README.md) is the full tour, this is the short list of
things to get right. Anything meant for every agent goes here; Claude Code
reads it through [CLAUDE.md](CLAUDE.md).

## What this is

A generic .NET 10 modular-monolith backend template. One deployable host
(`Starter.App`) composes several independent modules (`src/Modules/`), each
behind a narrow public interface, over shared cross-cutting machinery
(`Starter.Platform`) and domain primitives (`Starter.SharedKernel`). The
dependency graph flows one way:
`SharedKernel <- Platform <- Modules <- Api <- App`. Only the host references
everything; nothing references the host back.

## Build and test contract

```
export PATH="$HOME/.dotnet:$PATH"
dotnet build Starter.slnx -c Release
dotnet test  Starter.slnx -c Release
```

- The build is strict: nullable reference types on, warnings as errors
  (`Directory.Build.props`). A warning fails the build.
- Restore is locked and package versions are pinned centrally: package
  versions live once in `Directory.Packages.props` (central package
  management), and every project commits a `packages.lock.json`. Adding a
  package means a `PackageVersion` entry plus a `dotnet restore` to refresh
  the lock files; CI restores with `--locked-mode`, so a stale lock fails.
- The unit and architecture suites need no database. The integration suite
  (`tests/Starter.Integration.Tests`) boots the real host against a Postgres
  Testcontainer, so it needs a running Docker daemon.

## Module boundaries (the architecture tests enforce these)

`tests/Starter.Architecture.Tests` fails the build on a violation, so these
are not style suggestions:

- Each module assembly exports exactly two public types: its `I<Module>Api`
  interface and its `<Module>Module` bootstrap class. Everything else is
  `internal`, including the DbContext (one `<Module>DbContext` per module) and
  the generated migrations.
- Modules never reference each other. A module references only
  `Starter.SharedKernel` and `Starter.Platform`; the host composes modules and
  passes results across boundaries.
- Time and ids flow only through the SharedKernel: `DateTime.UtcNow` /
  `DateTimeOffset.UtcNow` and `Guid.NewGuid` / `Guid.CreateVersion7` are banned
  outside `Starter.SharedKernel`. Inject `Clock` for time and use `Ids` for
  UUIDv7 ids. `TimeProvider.System` is bound once, in the host.

## Adding a module

Follow the "Adding a module" steps in the [README](README.md). Do not
reinvent the recipe here; `Starter.Sample` is the worked example to copy (an
authenticated, owner-scoped resource with create / read / delete / keyset
list).

## Invariants to preserve

When you touch a feature, keep these intact - they are wired and enforced,
not aspirational:

- **RFC 9457 problem envelope.** Every error response is
  `application/problem+json` with a stable `starter:*` type slug and a trace
  id. Map failures through the `StarterProblems` / `ErrorResultExtensions`
  helpers; never hand-roll an error body.
- **Transactional outbox.** A domain event and its outbox rows commit in the
  same transaction as the state that produced them, and the event lands on the
  append-only `domain_events` spine. Enqueue through `OutboxWriter` inside the
  business transaction (see `CreateNoteHandler`); never emit events on a
  separate connection or after the commit.
- **Idempotency.** Non-idempotent requests are keyed so a retry replays the
  stored response instead of acting twice. Do not bypass the idempotency
  filter on mutating endpoints.
- **Resource-based authorization.** The access token carries no roles or
  scopes. Permission is resolved per request against the entity: mark it
  `IOwnedResource` and authorize an operation (`ResourceOperations.Read` /
  `Update` / `Delete`) with `IAuthorizationService`. Owner-scoped lists filter
  by owner in the query itself, not as an afterthought.
- **Validated options.** Bindable options are registered with
  `AddOptions<T>().Bind(section).ValidateDataAnnotations().ValidateOnStart()`
  so a misconfiguration fails at startup, not per request. Keep the shipped
  defaults valid so a zero-config host still boots, and keep optional
  integrations optional (do not force config that has no safe default).
- **Secrets never live in the repo.** No API keys, tokens, passwords,
  connection strings with credentials, or private keys in code, config,
  commits, or logs. Secrets belong in `dotnet user-secrets` locally and a
  managed secret store in production.

## Workflow and review gates

This repository is a standalone backend template: it ships no `.claude/`
commands, review-gate scripts, or docs-first workflow of its own. The full
docs-first process and the code/doc review gates live in the companion
`project-starter` template. Apply them from there when this repo is used
inside that workflow.
