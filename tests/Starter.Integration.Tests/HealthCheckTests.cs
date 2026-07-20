using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The host boots against a real Postgres with every module schema migrated
/// on startup: liveness answers, and readiness (Postgres reachable plus all
/// migrations applied) goes green.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class HealthCheckTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task Healthz_ReturnsOk()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var response = await fixture.Client.GetAsync("/healthz", cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Readyz_ReturnsOk_WithAllModuleSchemasMigrated()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var response = await fixture.Client.GetAsync("/readyz", cancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }
}
