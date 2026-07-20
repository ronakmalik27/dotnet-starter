using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Asp.Versioning;
using Asp.Versioning.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Starter.Api.Identity;
using Starter.Api.Sample;
using Starter.App.Persistence;
using Starter.Identity;
using Starter.Sample;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Events;
using Starter.Platform.Http;
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
            .AddHttpClientInstrumentation()
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

const string readyTag = "ready";
var healthChecks = builder.Services.AddHealthChecks();
if (postgres is not null)
{
    // The transactional outbox. Consumers register per module as they land;
    // with none, events still reach the domain_events spine and the
    // dispatcher idles as leader.
    builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(postgres));
    builder.Services.Configure<OutboxOptions>(builder.Configuration.GetSection("Outbox"));
    builder.Services.AddSingleton<OutboxMetrics>();
    builder.Services.AddSingleton<OutboxWriter>();
    builder.Services.AddSingleton<OutboxMaintenance>();
    builder.Services.AddSingleton<IdempotencyMaintenance>();
    builder.Services.AddSingleton<MigrationsHealthCheck>();
    builder.Services.AddHostedService<OutboxDispatcher>();

    // Module bootstrap: each module's single public extension contributes its
    // DbContext and schema descriptor; the platform schema registers through
    // the same path. Explicit calls, no scanning - the composition root names
    // what it composes.
    builder.Services
        .AddPlatformPersistence(postgres)
        .AddIdentityModule(postgres, signingKey, builder.Configuration)
        .AddSampleModule(postgres);

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
// without Postgres for UI-only work. Each module context migrates from its
// own assembly, so the schemas stay independent.
if (postgres is not null && builder.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
{
    await using var migrationScope = app.Services.CreateAsyncScope();
    foreach (var schema in migrationScope.ServiceProvider.GetServices<ModuleSchema>())
    {
        var context = (DbContext)migrationScope.ServiceProvider.GetRequiredService(schema.ContextType);
        await context.Database.MigrateAsync();
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
app.UseAuthorization();

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

    ApiVersionSet versionSet = app.NewApiVersionSet()
        .HasApiVersion(new ApiVersion(1))
        .ReportApiVersions()
        .Build();
    var versioned = app.MapGroup("/api/v{version:apiVersion}");
    versioned.WithApiVersionSet(versionSet).HasApiVersion(new ApiVersion(1));
    versioned.MapSampleEndpoints();
}

app.Run();

// Traces skip the health probes: they fire on a timer and would swamp the
// trace stream with no diagnostic value.
static bool IsProbePath(PathString path) =>
    path.StartsWithSegments("/healthz", StringComparison.OrdinalIgnoreCase)
    || path.StartsWithSegments("/readyz", StringComparison.OrdinalIgnoreCase);

// The integration suite boots this exact host through WebApplicationFactory.
public partial class Program;
