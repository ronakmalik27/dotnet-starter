using Xunit;

namespace Starter.Integration.Tests.Fixtures;

/// <summary>
/// The shared-host collection definition: one <see cref="StarterAppFixture"/>
/// (one container, one host) is reused across every test class in this
/// collection, so the expensive boot happens once.
/// </summary>
[CollectionDefinition(Name)]
public sealed class StarterCollectionDefinition : ICollectionFixture<StarterAppFixture>
{
    public const string Name = "starter-integration";
}
