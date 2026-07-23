using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Asp.Versioning;
using Asp.Versioning.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Starter.Api.Audit;
using Starter.Api.Auth;
using Starter.Api.Identity;
using Starter.Api.Platform;
using Starter.Api.Sample;
using Starter.Api.Tenancy;
using Starter.App.Persistence;
using Starter.Identity;
using Starter.Sample;
using Starter.Tenancy;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.DataProtection;
using Starter.Platform.Events;
using Starter.Platform.Http;
using Starter.Platform.Notifications;
using Starter.Platform.Tenancy;
using Starter.Platform.Webhooks;
using Starter.SharedKernel;

var builder = WebApplication.CreateBuilder(args);

// Structured logging: JSON to the console, scopes included so the
// correlation id the request-logging middleware pushes into scope shows up
// on every line. Clear the default text console provider first so logs are
// JSON only, not doubled.
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.UseUtcTimestamp = true;
});

// Composition root: the one place the wall clock is bound. Everything
// downstream takes Clock (or TimeProvider) by injection.
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<Clock>();

// Platform HTTP plumbing: the problem-mapper metrics and the idempotency
// filter's dependencies.
builder.Services.AddSingleton<PlatformHttpMetrics>();

// API versioning (URL-segment, default v1) and the OpenAPI document. The
// ApiExplorer integration substitutes the resolved version into the route
// template so the OpenAPI paths read /api/v1/... not /api/v{version}/...
builder.Services
    .AddApiVersioning(options =>
    {
        options.DefaultApiVersion = new ApiVersion(1);
        options.AssumeDefaultVersionWhenUnspecified = true;
        options.ReportApiVersions = true;
        options.ApiVersionReader = new UrlSegmentApiVersionReader();
    })
    .AddApiExplorer(options =>
    {
        options.GroupNameFormat = "'v'VVV";
        options.SubstituteApiVersionInUrl = true;
    });
builder.Services.AddOpenApi();

// CORS: origins come from configuration (Cors:AllowedOrigins). With none
// set the policy allows no cross-origin caller - same-origin only, the safe
// default for a fresh template.
const string corsPolicyName = "StarterCors";
var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(options =>
    options.AddPolicy(corsPolicyName, policy =>
    {
        if (corsOrigins.Length > 0)
        {
            policy
                .WithOrigins(corsOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        }
    }));

// Rate limiting: a global fixed-window limiter partitioned by client IP.
// The health probes opt out per-endpoint with DisableRateLimiting; a
// rejection is a bare 429 that the status-code problem mapper wraps in the
// same problem envelope.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));

    // A tighter named policy for anonymous self-serve signup: creating tenants
    // and accounts is abuse-sensitive, so it is bound well below the global
    // ceiling, partitioned by client IP. The per-minute count is configurable
    // (RateLimiting:SignupPerMinute) so a test or a trusted deployment can lift
    // it; the conservative default holds in production.
    var signupPerMinute = builder.Configuration.GetValue<int?>("RateLimiting:SignupPerMinute") ?? 5;
    options.AddPolicy(TenancyEndpoints.SignupRateLimitPolicy, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = signupPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
});

// Observability: vendor-neutral OpenTelemetry over OTLP, wired only when an
// endpoint is configured (OTEL_EXPORTER_OTLP_ENDPOINT), so local and test
// hosts boot clean with no exporter trying to reach a collector. Traces skip
// the health probes; metrics register the platform meters alongside the
// built-in ASP.NET Core, HttpClient, and runtime instrumentation.
var otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
if (!string.IsNullOrWhiteSpace(otlpEndpoint))
{
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource => resource.AddService(builder.Environment.ApplicationName))
        .WithTracing(tracing => tracing
            .AddAspNetCoreInstrumentation(instrumentation =>
                instrumentation.Filter = httpContext => !IsProbePath(httpContext.Request.Path))
            // Keep a tenant's receiver URL (which can embed a secret in its path) out of
            // traces: the webhook delivery client marks its requests and this enrichment
            // redacts the URL tags on those spans (webhooks.md section 5).
            .AddHttpClientInstrumentation(instrumentation =>
                instrumentation.EnrichWithHttpRequestMessage = WebhookTraceRedaction.Enrich)
            .AddOtlpExporter())
        .WithMetrics(metrics => metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddMeter(OutboxMetrics.MeterName)
            .AddMeter(PlatformHttpMetrics.MeterName)
            .AddOtlpExporter());
    builder.Logging.AddOpenTelemetry(logging =>
    {
        logging.IncludeScopes = true;
        logging.AddOtlpExporter();
    });
}

// Persistence wiring is fail-fast outside Development: without the connection
// string every idempotent and outbox path would 500 per-request while the
// process looked healthy. Development may boot without Postgres for UI-only
// work; readiness then answers 503, so the no-persistence mode is unreachable
// behind a ready signal. Empty and whitespace count as missing.
var configuredPostgres = builder.Configuration.GetConnectionString("Postgres");
var postgres = string.IsNullOrWhiteSpace(configuredPostgres) ? null : configuredPostgres;
if (postgres is null && !builder.Environment.IsDevelopment())
{
    throw new InvalidOperationException(
        "ConnectionStrings:Postgres is required outside Development (a host without persistence fails at startup, not per-request).");
}

// The ES256 access-token signing key, fail-fast like the connection string:
// a host that cannot sign or verify tokens must fail at startup, not
// per-request. Locally the PEM lives in dotnet user-secrets
// (Auth:SigningKeyPem); production injects it from a secret manager.
// Development without a configured key gets an ephemeral one - tokens die with
// the process, which is fine for local UI work and wrong for anything else.
var signingKeyPem = builder.Configuration["Auth:SigningKeyPem"];
var signingEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
if (!string.IsNullOrWhiteSpace(signingKeyPem))
{
    signingEcdsa.ImportFromPem(signingKeyPem);

    // KeySize alone proves neither "has a private key" (a public-only PEM
    // imports fine and reports the same KeySize, then fails later at the first
    // SignData call) nor "is P-256" (other curves share the 256 key size).
    // Export with private parameters and check the curve OID explicitly.
    ECParameters signingParameters;
    try
    {
        signingParameters = signingEcdsa.ExportParameters(includePrivateParameters: true);
    }
    catch (CryptographicException exception)
    {
        throw new InvalidOperationException(
            "Auth:SigningKeyPem must be the ES256 PRIVATE key: the host signs tokens, so a "
            + "public-key-only PEM cannot work here.",
            exception);
    }

    if (signingParameters.D is null || signingParameters.D.Length == 0)
    {
        throw new InvalidOperationException(
            "Auth:SigningKeyPem must be the ES256 private key: the imported PEM has no private component.");
    }

    if (!string.Equals(
        signingParameters.Curve.Oid.Value,
        ECCurve.NamedCurves.nistP256.Oid.Value,
        StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            "Auth:SigningKeyPem must be on the P-256 curve (ES256); got curve OID "
            + $"{signingParameters.Curve.Oid.Value ?? signingParameters.Curve.Oid.FriendlyName ?? "unknown"}.");
    }
}
else if (!builder.Environment.IsDevelopment())
{
    throw new InvalidOperationException(
        "Auth:SigningKeyPem is required outside Development (the ES256 signing key comes from a secret manager, never a default).");
}

var signingKey = new ECDsaSecurityKey(signingEcdsa);

// Local ES256 verification, no per-request DB hit. Registered even without
// persistence so the pipeline keeps its contract shape in every mode.
builder.Services.AddStarterJwtAuthentication(signingKey);

// The additive API-key scheme (service-accounts.md section 3): a forwarding
// policy scheme becomes the default authenticate scheme, routing
// `Authorization: Bearer sk_...` (or X-Api-Key) to the ApiKey handler and every
// other request to the JWT bearer scheme. The challenge stays Bearer, so the JWT
// 401 is unchanged and no authorization fallback policy is added.
builder.Services.AddStarterApiKeyAuthentication();

// Email transport: the console sender by default (logs the message,
// verification link included), SMTP when Email:Provider is smtp. No DB
// dependency, so it binds regardless of persistence.
builder.Services.AddStarterEmail(builder.Configuration);

const string readyTag = "ready";
var healthChecks = builder.Services.AddHealthChecks();

// Tenant isolation is enforced by Postgres row-level security, which only
// binds a NON-superuser, NON-BYPASSRLS role. The configured connection is the
// privileged admin credential (a superuser locally and in the Testcontainer);
// it is used ONLY to provision two derived roles and is never registered for
// request-scoped resolution. The request/consumer path connects as the RLS-
// bound role; migrations and the bypass data source connect as the BYPASSRLS
// role. See TenantRoleProvisioner for the derivation and the bootstrap below
// for role creation and grants.
TenantRoleProvisioner? tenantRoles = null;
if (postgres is not null)
{
    tenantRoles = TenantRoleProvisioner.FromAdminConnection(postgres);
    var requestConnection = tenantRoles.RequestConnectionString;

    // THE normal data source every request-scoped path resolves (idempotency
    // filter, outbox dispatcher, ProcessedEventStore): the RLS-bound role.
    builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(requestConnection));
    // The RLS-exempt escape hatch, a distinct type so request-scoped code
    // cannot resolve it by asking for an NpgsqlDataSource. Migrations, bootstrap,
    // and explicitly cross-tenant work use it; nothing else can.
    builder.Services.AddSingleton(_ =>
        new BypassDataSource(NpgsqlDataSource.Create(tenantRoles.BypassConnectionString)));
    // The request/consumer-scoped tenant context set by the resolution
    // middleware and the outbox dispatcher.
    builder.Services.AddStarterTenantContext(builder.Configuration);
    // Validated options: the numeric-range annotations are checked at startup,
    // so a bad Outbox override fails the boot rather than the dispatcher; the
    // defaults satisfy every annotation.
    builder.Services.AddOptions<OutboxOptions>()
        .Bind(builder.Configuration.GetSection("Outbox"))
        .ValidateDataAnnotations()
        .ValidateOnStart();
    // The durations carry no [Range] (TimeSpan has none), so a custom
    // IValidateOptions asserts they are sensible; registered as a singleton so
    // ValidateOnStart runs it at boot alongside the annotation checks.
    builder.Services.AddSingleton<IValidateOptions<OutboxOptions>, OutboxOptionsValidator>();
    builder.Services.AddSingleton<OutboxMetrics>();
    builder.Services.AddSingleton<OutboxWriter>();
    // The reusable at-least-once dedup store: consumers claim an event id
    // before acting on a non-transactional side effect. Singleton, built on
    // the shared data source.
    builder.Services.AddSingleton<ProcessedEventStore>();
    builder.Services.AddSingleton<OutboxMaintenance>();
    builder.Services.AddSingleton<IdempotencyMaintenance>();
    builder.Services.AddSingleton<MigrationsHealthCheck>();
    builder.Services.AddHostedService<OutboxDispatcher>();

    // Module bootstrap: each module's single public extension contributes its
    // DbContext and schema descriptor; the platform schema registers through
    // the same path. Explicit calls, no scanning - the composition root names
    // what it composes.
    builder.Services
        .AddPlatformPersistence(requestConnection)
        .AddIdentityModule(requestConnection, signingKey, builder.Configuration)
        .AddSampleModule(requestConnection)
        // Tenancy takes the request connection for its scoped context; its
        // provisioner, membership directory, and invitation acceptor additionally
        // inject the already-registered BypassDataSource singleton for their
        // cross-tenant work. Configuration carries the invitation link template
        // (Tenancy:Invitations). Its schema is migrated on the bypass connection
        // with the others (its ModuleSchema descriptor is picked up by the
        // bootstrap block below), so the request role gets its grants and RLS
        // binds it.
        .AddTenancyModule(requestConnection, builder.Configuration);

    // DataProtection persists its key ring to the platform context (keys
    // survive restarts and are shared across replicas). Needs the platform
    // context, so it lives inside the persistence block.
    builder.Services.AddPlatformDataProtection();

    // Outbound webhooks (webhooks.md section 10): the Fast-lane fan-out consumer, the
    // leader-elected delivery worker, the SSRF-guarded delivery HttpClient, the retention
    // pass, and the RLS-bound admin service. Lives in the persistence block: it needs the
    // platform context, the outbox, and the DataProtection key ring registered above.
    builder.Services.AddWebhooks(builder.Configuration);

    // Readiness: Postgres reachable via the same data source every request
    // path rides, and every schema's migrations applied. A bounded per-check
    // timeout keeps worst-case /readyz latency predictable.
    var probeTimeout = TimeSpan.FromSeconds(5);
    healthChecks
        .AddCheck<PostgresHealthCheck>("postgres", tags: [readyTag], timeout: probeTimeout)
        .AddCheck<MigrationsHealthCheck>("migrations", tags: [readyTag], timeout: probeTimeout);
}
else
{
    healthChecks.AddCheck(
        "postgres",
        () => HealthCheckResult.Unhealthy("No Postgres connection string is configured."),
        tags: [readyTag]);
}

var app = builder.Build();

// Migrate every module schema at startup when Database:MigrateOnStartup is
// set (the compose stack sets it, so `docker compose up` boots a ready host
// with no manual step). Off by default, so a local host can still boot
// without Postgres for UI-only work. The bootstrap owns the tenant-isolation
// setup end to end: first (re)provision the two roles on the admin connection,
// then migrate each schema on the BYPASS role (so it owns the tables and the
// FORCE-RLS owner-bypass rule applies), then grant the request role the DML
// rights it needs to work under RLS on the freshly-created tables.
if (postgres is not null && tenantRoles is not null
    && builder.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
{
    await tenantRoles.EnsureRolesAsync(CancellationToken.None);

    await using var migrationScope = app.Services.CreateAsyncScope();
    var schemas = migrationScope.ServiceProvider.GetServices<ModuleSchema>().ToList();
    foreach (var schema in schemas)
    {
        await MigrateSchemaAsync(migrationScope.ServiceProvider, schema, tenantRoles.BypassConnectionString);
    }

    await tenantRoles.GrantRequestRolePrivilegesAsync(
        schemas.Select(schema => schema.Name).Distinct(StringComparer.Ordinal).ToList(),
        CancellationToken.None);

    // The out-of-band first-platform-admin seed (multi-tenancy.md section 7):
    // when Platform:BootstrapAdminUserId names a user's guid, ensure that user is
    // a platform super-admin. It runs after migrations and grants, on the bypass
    // connection (platform tables live off the request role's reach), and is
    // idempotent. The first admin is NEVER self-granted through the API; this is
    // the only way one comes into being.
    var bootstrapAdmin = builder.Configuration["Platform:BootstrapAdminUserId"];
    if (Guid.TryParse(bootstrapAdmin, out var bootstrapAdminUserId) && bootstrapAdminUserId != Guid.Empty)
    {
        await PlatformAdminSeed.EnsureAsync(
            tenantRoles.BypassConnectionString, bootstrapAdminUserId, CancellationToken.None);
    }
}

// The request pipeline. Security headers and correlation/request logging are
// outermost so every response is hardened and every log line is correlated.
// The Development-only API-reference UI is exempt from the strict CSP so its
// assets can load.
var securityHeaderExemptions = app.Environment.IsDevelopment()
    ? new[] { "/scalar", "/openapi" }
    : [];
app.UseStarterSecurityHeaders(securityHeaderExemptions);
app.UseStarterCorrelationId();

// The problem mapper turns exceptions into RFC 9457 problem+json; the
// status-code companion wraps framework-generated bare statuses (a 401/403
// from auth, a 404 from routing, a 429 from the rate limiter) in the same
// envelope, so every API error wears one shape.
app.UseStarterProblemMapping();
app.UseStarterStatusCodeProblems();

app.UseCors(corsPolicyName);
app.UseRateLimiter();

app.UseAuthentication();

// The per-request impersonation guard runs immediately after authentication
// (the principal is populated) and before authorization and tenant resolution,
// so a request on an ended or expired impersonation grant is rejected with 401
// before any endpoint, gate, or tenant-scoped work runs. For a normal token
// (no imp claim) it is a single claim-presence check with no DB hit.
app.UseStarterImpersonationGuard();

app.UseAuthorization();

// Tenant resolution runs after authentication (it reads the tid claim off the
// signed principal) and before endpoint execution, so the request-scoped
// tenant is set before any handler opens a transaction. It never rejects a
// request; a tenant-scoped endpoint enforces its own requirement with
// RequireTenant.
app.UseStarterTenantResolution();

// OpenAPI document and the Scalar reference UI: Development only, anonymous,
// and outside the rate limiter. The document also feeds Scalar.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous().DisableRateLimiting();
    app.MapScalarApiReference();
}

// Health probes: outside the auth chain by construction, and exempt from the
// rate limiter (they fire on a timer). Liveness proves only that the process
// serves requests; readiness runs the ready-tagged checks. Responses are
// status words, never dependency detail.
app.MapHealthChecks("/healthz", new HealthCheckOptions { Predicate = _ => false })
    .AllowAnonymous()
    .DisableRateLimiting();
app.MapHealthChecks("/readyz", new HealthCheckOptions { Predicate = registration => registration.Tags.Contains(readyTag) })
    .AllowAnonymous()
    .DisableRateLimiting();

// Module endpoints. Identity and Sample need their stores, so the routes
// exist only when persistence does - the same boundary the readiness probe
// guards above. Sample hangs off the versioned route group (/api/v1/...).
if (postgres is not null)
{
    app.MapIdentityEndpoints();
    app.MapTenancyEndpoints();
    // The tenant-admin control plane (member/invitation management, settings,
    // ownership, soft-delete, seats), all over the active tenant (/api/v1/tenant).
    app.MapTenantAdminEndpoints();
    // The scoped-RBAC control plane (custom-role CRUD and role assignments), all
    // over the active tenant (/api/v1/tenant) and gated by RequirePermission.
    app.MapRoleAdminEndpoints();
    // The workspace control plane (multi-tenancy.md section 12): workspace CRUD
    // (tenant-scope gated) plus workspace-local roles and workspace-scoped grants
    // (workspace-scope gated), all under /api/v1/workspaces.
    app.MapWorkspaceAdminEndpoints();
    // The team control plane (multi-tenancy.md section 14): team CRUD and team-
    // member management, all over the active tenant (/api/v1/tenant/teams) and
    // gated by RequirePermission(teams:manage). A team is a principal that can
    // hold grants; the resolver unions its grants into each member's permissions.
    app.MapTeamAdminEndpoints();
    // The service-account control plane (service-accounts.md section 7): create,
    // list, rotate, and revoke API keys, all over the active tenant
    // (/api/v1/tenant/service-accounts) and gated by RequirePermission(api-keys:manage).
    // A service account is a non-human principal that authenticates with its key
    // (Authorization: Bearer sk_...) and carries scoped grants, not a membership.
    app.MapServiceAccountEndpoints();
    // The webhook control plane (webhooks.md section 7): register, list, update, rotate,
    // delete, delivery log, and replay, all over the active tenant
    // (/api/v1/tenant/webhooks) and gated by RequirePermission(webhooks:manage).
    app.MapWebhookEndpoints();
    // The tenant feature-flag surface (feature-flags.md section 5): the resolved-flag
    // list plus the tenant's own tenant/workspace override set/clear, all over the
    // active tenant (/api/v1/tenant/feature-flags) and gated by
    // RequirePermission(feature-flags:manage). The super-admin flag catalogue lives on
    // the platform plane (mapped by MapPlatformAdminEndpoints). The RequireFeatureFlag
    // endpoint gate ships unused on live routes by design; its demonstration route maps
    // ONLY when FeatureFlags:GateDemoEnabled is set (the test host), never in production.
    app.MapTenantFeatureFlagEndpoints();
    if (builder.Configuration.GetValue<bool>(FeatureFlagEndpoints.GateDemoConfigKey))
    {
        app.MapFeatureFlagGateDemoEndpoints();
    }

    // The usage report (quotas.md section 7): the plan's limits, metered
    // current-period usage, and resource-count gauges, over the active tenant
    // (/api/v1/tenant/usage) and gated by seats:read. The RequireQuota metered gate
    // ships unused on live routes by design; its demonstration route
    // (/api/v1/tenant/quota-demo, gated RequireQuota("demo_calls")) maps ONLY when
    // Quotas:DemoEnabled is set (the test host), never in production.
    app.MapUsageEndpoints();
    if (builder.Configuration.GetValue<bool>(UsageEndpoints.DemoConfigKey))
    {
        app.MapQuotaDemoEndpoints();
    }

    // The workspace-scoped view of the Sample resource
    // (/api/v1/workspaces/{workspaceId}/sample/notes): the worked example of a
    // workspace-scoped resource, gated by notes:read / notes:write at the workspace.
    app.MapWorkspaceSampleEndpoints();
    // The platform super-admin plane (cross-tenant tenant lifecycle, the
    // platform-admin roster, audited impersonation), all under /api/v1/platform
    // and gated by RequirePlatformAdmin - never a tenant role.
    app.MapPlatformAdminEndpoints();
    // The audit log (audit-log.md section 6): the tenant-admin read over the
    // active tenant (/api/v1/tenant/audit, gated by audit:read, RLS-scoped) and
    // the super-admin cross-tenant read (/api/v1/platform/audit, behind
    // RequirePlatformAdmin, with a tenant filter and a scope=platform selector).
    app.MapTenantAuditEndpoints();
    app.MapPlatformAuditEndpoints();

    ApiVersionSet versionSet = app.NewApiVersionSet()
        .HasApiVersion(new ApiVersion(1))
        .ReportApiVersions()
        .Build();
    var versioned = app.MapGroup("/api/v{version:apiVersion}");
    versioned.WithApiVersionSet(versionSet).HasApiVersion(new ApiVersion(1));
    versioned.MapSampleEndpoints();
}

app.Run();

// Migrates one module schema on the bypass role. The request contexts are
// wired to the RLS-bound role, so migrations (which own the tables) need
// bypass-role options built for the runtime context type: ForSchema is
// generic, reached reflectively; ActivatorUtilities fills the context's
// ITenantContext (unresolved at bootstrap, so the interceptor is a no-op).
static async Task MigrateSchemaAsync(
    IServiceProvider services, ModuleSchema schema, string bypassConnectionString)
{
    var optionsBuilder = (DbContextOptionsBuilder)typeof(StarterDbContextOptions)
        .GetMethod(nameof(StarterDbContextOptions.ForSchema))!
        .MakeGenericMethod(schema.ContextType)
        .Invoke(null, [bypassConnectionString, schema.Name])!;
    var context = (DbContext)ActivatorUtilities.CreateInstance(
        services, schema.ContextType, optionsBuilder.Options);
    await using (context.ConfigureAwait(false))
    {
        await context.Database.MigrateAsync();
    }
}

// Traces skip the health probes: they fire on a timer and would swamp the
// trace stream with no diagnostic value.
static bool IsProbePath(PathString path) =>
    path.StartsWithSegments("/healthz", StringComparison.OrdinalIgnoreCase)
    || path.StartsWithSegments("/readyz", StringComparison.OrdinalIgnoreCase);

// The integration suite boots this exact host through WebApplicationFactory.
public partial class Program;
