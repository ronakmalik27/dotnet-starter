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

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17")
        .Build();

    private WebApplicationFactory<Program>? _factory;

    /// <summary>The captured outbound mailbox.</summary>
    public CapturingEmailSender Emails { get; } = new();

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
