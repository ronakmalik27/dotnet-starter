using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// The single source of truth for the module set under architecture test.
/// Every rule derives its cases from this list, so a new module is added
/// here exactly once and the dependency-shape, surface, and naming rules
/// all pick it up together.
/// </summary>
public static class StarterModules
{
    public static readonly IReadOnlyList<Type> ApiTypes =
    [
        typeof(Starter.Identity.IIdentityApi),
        typeof(Starter.Sample.ISampleApi),
        typeof(Starter.Tenancy.ITenancyApi),
    ];

    public static TheoryData<Type> ApiTypeData()
    {
        var data = new TheoryData<Type>();
        foreach (var apiType in ApiTypes)
        {
            data.Add(apiType);
        }

        return data;
    }
}
