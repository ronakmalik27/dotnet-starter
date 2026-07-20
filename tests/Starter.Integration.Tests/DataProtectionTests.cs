using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// DataProtection persists its key ring to Postgres (Feature 3). Protecting
/// then unprotecting round-trips, and doing so materializes at least one key
/// row in platform.data_protection_keys - proof the keys live in the DB, not
/// on the container filesystem where they would vanish on restart.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class DataProtectionTests(StarterAppFixture fixture)
{
    [Fact]
    public async Task Protect_RoundTrips_AndPersistsKeyToPostgres()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var provider = fixture.Factory.Services.GetRequiredService<IDataProtectionProvider>();
        var protector = provider.CreateProtector("integration-test");

        var protectedPayload = protector.Protect("round-trip me");
        protector.Unprotect(protectedPayload).ShouldBe("round-trip me");

        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "select count(*) from platform.data_protection_keys", connection);

        var count = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
        count.ShouldBeGreaterThan(0);
    }
}
