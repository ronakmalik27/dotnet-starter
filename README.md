# Starter

A generic .NET 10 modular-monolith backend template. It is a batteries-included
starting point: one deployable host, several independent modules behind narrow
public interfaces, and the cross-cutting machinery a real service needs wired up
and enforced from day one.

## What you get

- **Modular monolith.** Each module (see `src/Modules/`) exposes exactly one
  public interface (`I<Module>Api`) plus one bootstrap class (`<Module>Module`);
  everything else is internal. Modules never reference each other - the host
  composes them. Architecture tests fail the build if a module leaks a type or
  reaches across a boundary.
- **Authentication (Identity module).** ES256 JWT access tokens, password auth
  with Argon2id hashing, Google OIDC sign-in (authorization-code flow with PKCE
  and nonce), refresh-token sessions with reuse detection, and email
  verification (register and resend send the verification link through the email
  transport below).
- **Email / notifications.** A pluggable `IEmailSender` seam with two transports:
  a console sender (the default - it logs the whole message, verification link
  included, so local development needs no mail server) and a MailKit SMTP sender
  for real delivery. Pick the transport with `Email:Provider`.
- **DataProtection key persistence.** ASP.NET DataProtection keys persist to
  Postgres (the platform schema), so they survive restarts and are shared across
  replicas instead of regenerating per instance. Nothing consumes DataProtection
  yet - this is the correct scale-out default set ahead of the first
  DP-dependent feature (cookie auth, antiforgery, OIDC middleware).
- **RFC 9457 problem details.** Every error - thrown, returned, or framework
  generated - leaves as `application/problem+json` with a stable type slug and a
  trace id.
- **Transactional outbox.** Domain events and their outbox rows commit in the
  same transaction as the state that produced them, then dispatch at-least-once
  to in-process consumers.
- **Idempotency.** A filter keys retries of non-idempotent requests so a repeat
  replays the stored response instead of acting twice.
- **Observability.** Vendor-neutral OpenTelemetry (traces, metrics, logs) over
  OTLP, plus structured JSON logs with a correlation id on every line. No
  cloud-vendor lock-in.
- **Health checks.** `/healthz` (liveness) and `/readyz` (readiness: Postgres
  reachable and every module's migrations applied).
- **API surface.** URL-segment API versioning (default `v1`), a built-in OpenAPI
  document, and the Scalar reference UI in Development.
- **Hardening.** Global rate limiting, configurable CORS, and baseline security
  headers (nosniff, frame-deny, no-referrer, a strict CSP).

## Layout

```
src/
  Starter.SharedKernel/   Domain primitives: Result/Error, Clock, Ids (UUIDv7). No dependencies.
  Starter.Platform/       Cross-cutting infra: persistence, outbox, idempotency, problem mapping,
                          JWT verification, email transport (Notifications/), DataProtection key
                          persistence, and the security-headers / correlation-id middleware.
  Starter.Api/            HTTP endpoint composition over the module interfaces.
  Starter.App/            The host and composition root: DI wiring, the request pipeline, hosted services.
  Modules/
    Starter.Identity/     The authentication module.
    Starter.Sample/       The worked example - copy this to start a new module.
tests/
  Starter.SharedKernel.Tests/
  Starter.Platform.Tests/
  Starter.Identity.Tests/
  Starter.Architecture.Tests/   Enforces the module boundaries and banned-API rules.
  Starter.Integration.Tests/    End-to-end over the real host and a Postgres Testcontainer.
```

The dependency graph flows one way: `SharedKernel <- Platform <- Modules <- Api <- App`.
Only the App references everything; nothing references the App back.

## Running it

### With Docker Compose (recommended)

```
docker compose up --build
```

This starts Postgres and the app. The app waits for Postgres to report healthy,
applies every module's migrations on startup (`Database__MigrateOnStartup=true`
in the compose file), and then serves on port 8080.

- Liveness: http://localhost:8080/healthz
- Readiness: http://localhost:8080/readyz
- API reference UI (Development): http://localhost:8080/scalar
- OpenAPI document: http://localhost:8080/openapi/v1.json

### Locally with the .NET SDK

Start a Postgres that matches the dev connection string (user `starter`, password
`starter`, database `starter`) - for example:

```
docker run --rm -e POSTGRES_USER=starter -e POSTGRES_PASSWORD=starter \
  -e POSTGRES_DB=starter -p 5432:5432 postgres:17
```

Apply migrations (each module context owns its schema), then run the host:

```
export PATH="$HOME/.dotnet:$PATH"
dotnet tool install --global dotnet-ef   # once, if you do not have it

dotnet ef database update --project src/Starter.Platform --context PlatformDbContext
dotnet ef database update --project src/Modules/Starter.Identity --context IdentityDbContext
dotnet ef database update --project src/Modules/Starter.Sample --context SampleDbContext

dotnet run --project src/Starter.App
```

Or set `Database:MigrateOnStartup` to `true` (config or `Database__MigrateOnStartup=true`
env var) to have the host apply migrations itself. In Development the host also
boots without Postgres for UI-only work; `/readyz` then reports 503.

### Observability export

Set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_SERVICE_NAME`) to an OTLP
collector to turn on trace, metric, and log export. Left unset, the app runs with
no exporter attached.

### Configuration keys

| Key | Purpose | Default |
|---|---|---|
| `ConnectionStrings:Postgres` | Postgres connection string | required outside Development |
| `Auth:SigningKeyPem` | ES256 private key (PEM) for JWT signing | ephemeral in Development, required elsewhere |
| `Auth:Google` | Google OIDC options (client id/secret, redirect) | Google sign-in returns 501 when absent |
| `Auth:Verification:UrlTemplate` | Verify-email link template; `{token}` is replaced with the URL-encoded token | `https://localhost:3000/verify-email?token={token}` |
| `Email:Provider` | Email transport: `console` or `smtp` | `console` |
| `Email:FromAddress` / `Email:FromName` | From identity stamped on sent mail | `no-reply@starter.example` / `Starter` |
| `Email:Smtp:Host` / `Email:Smtp:Port` | SMTP server host and port (smtp provider) | `localhost` / `587` |
| `Email:Smtp:Username` / `Email:Smtp:Password` | SMTP credentials; password from a secret store, never a default | unset (send unauthenticated) |
| `Email:Smtp:UseStartTls` | Upgrade the SMTP connection with STARTTLS | `true` |
| `Cors:AllowedOrigins` | Allowed CORS origins (array) | none (same-origin only) |
| `Database:MigrateOnStartup` | Apply migrations on boot | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | unset (export off) |

Secrets live in `dotnet user-secrets` locally and a secret manager in production -
never in the repo.

## Adding a module

`Starter.Sample` is the worked example. To add a `Widgets` module:

1. Copy `src/Modules/Starter.Sample` to `src/Modules/Starter.Widgets` and rename
   the project, namespaces, `ISampleApi` -> `IWidgetsApi`, `SampleModule` ->
   `WidgetsModule`, and `SampleDbContext` -> `WidgetsDbContext` (its own schema
   name). Keep the public surface at exactly the interface plus the bootstrap
   class; everything else internal.
2. Model your entity with a UUIDv7 id from `Ids` and timestamps from `Clock`
   (never `Guid.NewGuid` or `DateTime.UtcNow` - the architecture tests ban them
   outside the SharedKernel). Emit domain events through the platform
   `OutboxWriter` inside the business transaction, as `CreateNoteHandler` does.
3. Generate the initial migration:
   `dotnet ef migrations add Initial --project src/Modules/Starter.Widgets --context WidgetsDbContext -o Migrations`
   and make the generated migration class `internal` so it stays off the public
   surface.
4. Reference the new project from `Starter.Api` and `Starter.App`, add it to the
   solution and the `Starter.Architecture.Tests` project, and list its
   `I<Module>Api` in `tests/Starter.Architecture.Tests/StarterModules.cs`.
5. Call `AddWidgetsModule(...)` in `Program.cs` next to `AddSampleModule`, and map
   its endpoints under the versioned route group.

## Build and test

```
export PATH="$HOME/.dotnet:$PATH"
dotnet build Starter.slnx
dotnet test  Starter.slnx
```

The build contract is strict (`Directory.Build.props`): nullable reference types
on, warnings as errors, and lock-file restore. Package versions are pinned once
in `Directory.Packages.props` (central package management).

The unit and architecture suites need no database. The integration suite
(`tests/Starter.Integration.Tests`) boots the real host with
`WebApplicationFactory` against a Postgres Testcontainer, so it needs a running
Docker daemon; `dotnet test Starter.slnx` runs it alongside the rest. CI runs it
in its own job (GitHub-hosted runners provide Docker).

## License

MIT. See [LICENSE](LICENSE).
