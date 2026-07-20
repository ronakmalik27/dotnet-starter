using Shouldly;
using Starter.Platform.Data;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// One DbContext per module schema. Exactly one context
/// per module assembly, derived from ModuleDbContext, and internal (the
/// surface rules in <see cref="ModuleSurfaceTests"/> already ban it from
/// being public; this pins its existence and shape).
/// </summary>
public class ModuleDataTests
{
    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void Module_HasExactlyOneModuleDbContext(Type moduleApiType)
    {
        var contexts = moduleApiType.Assembly.GetTypes()
            .Where(type => type.IsSubclassOf(typeof(ModuleDbContext)))
            .ToList();

        var context = contexts.ShouldHaveSingleItem();
        context.IsPublic.ShouldBeFalse();
        context.Name.ShouldBe($"{moduleApiType.Assembly.GetName().Name!["Starter.".Length..]}DbContext");
    }
}
