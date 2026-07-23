using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Starter.Platform.Notifications;
using Starter.Platform.Tenancy;
using Starter.Platform.Webhooks;
using Testcontainers.PostgreSql;
using Xunit;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// Boots the real host once for the whole test collection: a Postgres 17
/// Testcontainer, then a <see cref="WebApplicationFactory{TEntryPoint}"/>
/// pointed at it with migrate-on-startup on and an ephemeral ES256 signing
/// key, so every module schema migrates on boot and token issuance works.
/// The email transport is replaced with a capturing fake so tests can read
/// verification links.
/// </summary>
public sealed class StarterAppFixture : IAsyncLifetime
{
    // Environment-variable configuration keys (":" nesting becomes "__").
    private const string EnvironmentKey = "ASPNETCORE_ENVIRONMENT";
    private const string PostgresKey = "ConnectionStrings__Postgres";
    private const string MigrateKey = "Database__MigrateOnStartup";
    private const string SigningKeyKey = "Auth__SigningKeyPem";

    // Lift the anonymous-signup rate limit for the shared test host. Production
    // caps signup at a few per minute per IP; every in-process test request
    // shares one partition (no distinct client IP), so a real cap would 429 the
    // provisioning suite. The limiter's mapping is not the subject here - the
    // signup endpoint's named policy reads this config value, so the test host
    // sets it far above any test's volume.
    private const string SignupRateLimitKey = "RateLimiting__SignupPerMinute";

    // Maps the RequireFeatureFlag gate demonstration endpoint (feature-flags.md
    // section 4): the filter ships unused on live routes by design, so the demo
    // route exists only when this toggle is set - the test host sets it so the
    // fail-closed test can exercise the real filter over HTTP; production leaves it off.
    private const string FeatureFlagGateDemoKey = "FeatureFlags__GateDemoEnabled";

    // Maps the RequireQuota metered-gate demonstration endpoint (quotas.md section
    // 5), the same map-time-filter pattern: the demo route exists only when this
    // toggle is set, so the metered-ceiling test can exercise the real filter over
    // HTTP; production leaves it off and no live route is metered by default.
    private const string QuotaDemoKey = "Quotas__DemoEnabled";

    // Webhook worker tuning for a fast, deterministic suite plus the loopback allowance
    // (WebhookOptions is bound from config, so these ride environment variables like the
    // connection string). AllowLoopbackDelivery relaxes ONLY loopback so the worker can
    // reach a test-local receiver; every other blocked SSRF range stays blocked.
    private static readonly (string Key, string Value)[] WebhookEnvironment =
    [
        ("Webhooks__AllowLoopbackDelivery", "true"),
        ("Webhooks__PollInterval", "00:00:00.2"),
        ("Webhooks__MaxAttempts", "3"),
        ("Webhooks__MaxBackoff", "00:00:00.5"),
        ("Webhooks__MaxJitter", "00:00:00"),
        ("Webhooks__SendTimeout", "00:00:03"),
        ("Webhooks__LeaderRetryInterval", "00:00:01"),
    ];

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17")
        .Build();

    private WebApplicationFactory<Program>? _factory;

    /// <summary>The captured outbound mailbox.</summary>
    public CapturingEmailSender Emails { get; } = new();

    /// <summary>
    /// The test webhook DNS resolver: tests map hostnames to chosen addresses so the SSRF
    /// guard is exercisable (including the DNS-rebinding case) without real DNS.
    /// </summary>
    internal TestWebhookDnsResolver WebhookDns { get; } = new();

    /// <summary>A client bound to the in-process host. Cookies are handled
    /// manually by the tests (the refresh cookie is Secure), so auto cookie
    /// handling is off.</summary>
    public HttpClient Client { get; private set; } = default!;

    /// <summary>The running host, for resolving framework services in tests.</summary>
    public WebApplicationFactory<Program> Factory => _factory
        ?? throw new InvalidOperationException("Fixture not initialized.");

    /// <summary>The container connection string (the admin superuser), for direct SQL seeding and assertions - bypasses RLS.</summary>
    public string ConnectionString => _postgres.GetConnectionString();

    /// <summary>
    /// The RLS-bound request-role data source (the same one every request path
    /// uses). Isolation tests open raw connections here to prove RLS holds
    /// below EF - the request role is subject to the tenant policy.
    /// </summary>
    public NpgsqlDataSource RequestDataSource =>
        Factory.Services.GetRequiredService<NpgsqlDataSource>();

    /// <summary>
    /// The RLS-exempt bypass-role data source (the escape hatch). Isolation
    /// tests use it to prove it, and only it, crosses tenants.
    /// </summary>
    public NpgsqlDataSource BypassDataSource =>
        Factory.Services.GetRequiredService<BypassDataSource>().DataSource;

    public async ValueTask InitializeAsync()
    {
        await _postgres.StartAsync();

        // The host reads ConnectionStrings:Postgres and Auth:SigningKeyPem in
        // its top-level statements, before it builds - earlier than any
        // WithWebHostBuilder(ConfigureAppConfiguration) source applies. So the
        // values go in as environment variables, which the builder's
        // configuration already includes at that point, and which also beat
        // appsettings. Production keeps appsettings.Development.json out of
        // the picture entirely. All are cleared in DisposeAsync.
        Environment.SetEnvironmentVariable(EnvironmentKey, Environments.Production);
        Environment.SetEnvironmentVariable(PostgresKey, _postgres.GetConnectionString());
        Environment.SetEnvironmentVariable(MigrateKey, "true");
        Environment.SetEnvironmentVariable(SigningKeyKey, CreateEs256PrivateKeyPem());
        Environment.SetEnvironmentVariable(SignupRateLimitKey, "100000");
        Environment.SetEnvironmentVariable(FeatureFlagGateDemoKey, "true");
        Environment.SetEnvironmentVariable(QuotaDemoKey, "true");
        foreach (var (key, value) in WebhookEnvironment)
        {
            Environment.SetEnvironmentVariable(key, value);
        }

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                // Swap the real transport for the capturing fake. This runs
                // after the host's own service registration, so it wins.
                services.RemoveAll<IEmailSender>();
                services.AddSingleton<IEmailSender>(Emails);

                // Lift the global rate-limit ceiling for the test host only.
                // Production applies a 100-requests/minute limiter partitioned
                // by client IP; every in-process test request shares one
                // partition (the TestServer presents no distinct client IP), so
                // the whole collection would draw on a single 100/min bucket
                // and later tests would hit spurious 429s as the suite grows.
                // The limiter's mapping is unit-tested elsewhere and is not the
                // subject here, so the test host swaps in a no-op limiter rather
                // than letting the ceiling throttle the shared run. This
                // Configure callback runs after the host's, so it wins.
                services.Configure<RateLimiterOptions>(rateLimiter =>
                    rateLimiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                        _ => RateLimitPartition.GetNoLimiter("test")));

                // Substitute the test DNS resolver so the SSRF guard resolves through a
                // seam the tests control (this Configure runs after the host's, so it wins).
                // The webhook worker's timings and the loopback allowance are set via
                // environment variables (WebhookOptions uses init-only setters, bound from
                // config), in InitializeAsync below.
                services.RemoveAll<IWebhookDnsResolver>();
                services.AddSingleton<IWebhookDnsResolver>(WebhookDns);
            }));

        // Building the client triggers host startup, which runs every
        // module's migrations (Database:MigrateOnStartup).
        Client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
    }

    public async ValueTask DisposeAsync()
    {
        Client?.Dispose();
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        await _postgres.DisposeAsync();

        Environment.SetEnvironmentVariable(EnvironmentKey, null);
        Environment.SetEnvironmentVariable(PostgresKey, null);
        Environment.SetEnvironmentVariable(MigrateKey, null);
        Environment.SetEnvironmentVariable(SigningKeyKey, null);
        Environment.SetEnvironmentVariable(SignupRateLimitKey, null);
        Environment.SetEnvironmentVariable(FeatureFlagGateDemoKey, null);
        Environment.SetEnvironmentVariable(QuotaDemoKey, null);
        foreach (var (key, _) in WebhookEnvironment)
        {
            Environment.SetEnvironmentVariable(key, null);
        }
    }

    /// <summary>
    /// Registers an account, verifies its email from the captured link, logs
    /// in, and returns the access token - the full password onboarding
    /// (AuthFlowTests, condensed) so a test that needs an authenticated caller
    /// gets a bearer token in one call. Use a unique email per caller so the
    /// shared mailbox stays unambiguous.
    /// </summary>
    public async Task<string> RegisterVerifyLoginAsync(
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var register = await Client.PostAsJsonAsync(
            "/api/v1/auth/register", new { email, password }, cancellationToken);
        register.EnsureSuccessStatusCode();

        var verificationEmail = Emails.Sent.Last(message => message.To == email);
        var token = HttpTestHelpers.ExtractVerificationToken(verificationEmail);

        var verify = await Client.PostAsJsonAsync(
            "/api/v1/auth/verify-email", new { token }, cancellationToken);
        verify.EnsureSuccessStatusCode();

        var login = await Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password }, cancellationToken);
        login.EnsureSuccessStatusCode();

        using var doc = await HttpTestHelpers.ReadJsonAsync(login, cancellationToken);
        return doc.RootElement.GetProperty("accessToken").GetString()
            ?? throw new InvalidOperationException("Login returned no access token.");
    }

    /// <summary>Opens a fresh connection to the container database.</summary>
    public async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static string CreateEs256PrivateKeyPem()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }
}
